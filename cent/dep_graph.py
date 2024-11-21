'''
 # @ Create Time: 2024-11-17 12:01:10
 # @ Modified time: 2024-11-17 12:01:21
 # @ Description: extract the dependency nodes only and construct new dependency based on timeline info
 '''

from collections import defaultdict
from multiprocessing import Pool, cpu_count
from pathlib import Path
import logging
import pickle
import networkx as nx
from functools import partial
from tqdm import tqdm
import os
import uuid

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('dep_graph.log')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)


# Define a wrapper function for processing chunks
def process_wrapper(chunk,release_nodes, time_ranges, nodes, rel_to_soft, get_timestamp, is_release):
        return process_edges_chunk(
            chunk, release_nodes, time_ranges, nodes, rel_to_soft, get_timestamp, is_release
    )


def process_edges_chunk(chunk, release_nodes, time_ranges, nodes, rel_to_soft, 
                    get_timestamp, is_release):
    """
    Worker function to process a chunk of edges.
    """
    local_graph = nx.DiGraph()
    rel_to_soft_map = rel_to_soft()
    for src, tgt, _ in chunk:
        if is_release(nodes[src]):  # Only consider release nodes for the source
            src_range = time_ranges.get(src, (0, float('inf')))
            if not is_release(nodes[tgt]):  # If the target is a software node
                # Get all releases for the target software
                if tgt in rel_to_soft_map:  # Check if the software has associated releases
                    for release in rel_to_soft_map[tgt]:  # Iterate through all releases of the software
                        if release in release_nodes:  # Ensure the release exists in the graph
                            tgt_timestamp = get_timestamp(nodes[release])  # Timestamp of the target release
                            if src_range[0] <= tgt_timestamp < src_range[1]:  # Check if within range
                                local_graph.add_edge(src, release)  # Add edge between releases

            elif is_release(nodes[tgt]):  # If the target is also a release
                tgt_timestamp = get_timestamp(nodes[tgt])  # Timestamp of the target release
                if src_range[0] <= tgt_timestamp < src_range[1]:
                    local_graph.add_edge(src, tgt)  # Add direct edge between releases
    
    # save the subgraph to disk
    subgraph_file = Path.cwd().parent.joinpath('data', f"subgraph_{os.getpid()}_{uuid.uuid4().hex}.graphml")
    nx.write_graphml(local_graph, subgraph_file)

    return subgraph_file

class DepGraph:
    def __init__(self, nodes, edges):
        self.nodes = nodes
        self.edges = edges
    
    def cve_check(self, node:dict):
        if 'type' in node and node['type'] == "CVE" and self.str_to_json(node["value"])['cve'] !=[]:
            return True
        else:
            return False

    def get_timestamp(self, node: dict):
        return int(node.get("timestamp", 0))
    
    def covt_ngb_format(self,):
        node_ngbs = {}

        for source, target in self.edges:
            node_ngbs.setdefault(source, []).append(target)
        
        return node_ngbs

    def is_release(self, node: dict):
        if node["labels"] == ":Release":
            return True
        else:
            return False

    def get_releases(self,):
        return {node_id: data for node_id, data in self.nodes.items() if data['labels'] == ":Release"}
    
    def get_cve_releases(self,):
        return {node_id: data for node_id, data in self.nodes.items() if data['labels'] == ":Release" and self.cve_check(data)}

    def rel_to_soft(self):
        ''' build the dict to map parent software to release
        
        
        '''
        release_to_software = {}

        for src, tgt, attr in self.edges:
            if attr['label'] == "dependency":
                # source is software, target is release
                release_to_software[tgt] = src
            elif attr['label'] == 'relationship_AR':
                release_to_software[src] = tgt

        return release_to_software

    def soft_to_rel(self, release_to_software: dict):
        ''' group releases by software using the mapping
        
        '''
        software_releases = defaultdict(list)

        for release, software in release_to_software.items():
            timestamp = self.get_timestamp(self.nodes[release])  
            software_releases[software].append((release, timestamp))

        # sort releases for each software by timestamp
        for software, releases in software_releases.items():
            software_releases[software] = sorted(releases, key=lambda x: x[1])

        return software_releases

    def time_ranges(self, software_to_release: dict):
        timestamp_ranges = {}
        for software, releases in software_to_release.items():
            timestamps = [ts for _, ts in releases] + [float('inf')]  # Add open-ended range
            for i, (nid, timestamp) in enumerate(releases):
                timestamp_ranges[nid] = (timestamp, timestamps[i + 1])
        return timestamp_ranges

    def filter_edges(self, software_to_releases):
        filter_edges = []
        for src, tgt, attr in self.edges:
            if attr['label'] in {'dependency', 'relationship_AR'}:
                yield (src, tgt if attr['label'] == 'dependency' else tgt, src)
    
    def chunk_generator(self, generator, chunk_size):
        """
        Breaks a generator into chunks of size `chunk_size`.
        """
        chunk = []
        for item in generator:
            chunk.append(item)
            if len(chunk) == chunk_size:
                yield chunk
                chunk = []
        if chunk:  # Yield remaining items
            yield chunk

    def dep_graph_build_parallel(self, filter_edges, time_ranges):
        """
        Parallelized version of dep_graph_build.
        """
        # Get release nodes
        # release_nodes = self.get_releases()
        release_nodes = self.get_cve_releases()
        # Precompute other reusable data
        nodes = self.nodes
        rel_to_soft = self.rel_to_soft
        get_timestamp = self.get_timestamp
        is_release = self.is_release
        
        # Split edges into chunks for parallel processing
        num_processes = cpu_count()
        chunk_size = 200000
        edge_chunks = self.chunk_generator(filter_edges, chunk_size)
        
        # Use multiprocessing pool to process chunks in parallel
        with Pool(processes=num_processes) as pool:
            subgraph_files = list(tqdm(
                pool.imap(
                    partial(process_wrapper,  # Pass the global function
                            release_nodes=release_nodes, time_ranges=time_ranges, nodes=nodes,
                            rel_to_soft=rel_to_soft, get_timestamp=get_timestamp, is_release=is_release),
                    edge_chunks
                ),
                desc="Parallel graph build",
            ))

        # Combine all subgraphs into one graph
        combined_graph = nx.DiGraph()
        for subgraph_file in subgraph_files:
            subgraph = nx.read_graphml(subgraph_file)
            combined_graph.update(subgraph)
            os.remove(subgraph_file)
        
        return combined_graph

    # def dep_graph_build(self, filter_edges, time_ranges):
    #     new_graph = nx.DiGraph()
    #     # get release nodes
    #     release_nodes = self.get_releases()
    #     for nid, data in release_nodes.items():
    #         new_graph.add_node(nid, **data)
        
    #     # add edges based on timestamp range conditions
    #     for src, tgt in tqdm(filter_edges, desc="building new graph based on release dependencies", total=len(filter_edges)):
    #         if self.is_release(self.nodes[src]):  # Only consider release nodes for the source
    #             src_range = time_ranges.get(src, (0, float('inf')))  
    #             if not self.is_release(self.nodes[tgt]):  # If the target is a software node
    #                 # Get all releases for the target software
    #                 if tgt in self.rel_to_soft():  # Check if the software has associated releases
    #                     for release in self.rel_to_soft()[tgt]:  # Iterate through all releases of the software
    #                         if release in release_nodes:  # Ensure the release exists in the graph
    #                             tgt_timestamp = self.get_timestamp(self.nodes[release])  # Timestamp of the target release
    #                             if src_range[0] <= tgt_timestamp < src_range[1]:  # Check if within range
    #                                 new_graph.add_edge(src, release)  # Add edge between releases

    #             elif self.is_release(self.nodes[tgt]):  # If the target is also a release
    #                 tgt_timestamp = self.get_timestamp(self.nodes[tgt])  # Timestamp of the target release
    #                 if src_range[0] <= tgt_timestamp < src_range[1]:
    #                     new_graph.add_edge(src, tgt)  # Add direct edge between releases

    #     return new_graph

    def graph_save(self, new_graph, graph_path):
        with graph_path.open('wb') as fw:
            pickle.dump(new_graph, fw)
    
    def graph_load(self, graph_path):
        with graph_path.open('rb') as fr:
            return pickle.load(fr)


def load_data(file_path):
    with file_path.open('rb') as f:
        data = pickle.load(f)
    return data['nodes'], data['edges']

if __name__ == "__main__":

    # nodes_edges_path = Path.cwd().parent.joinpath("data", 'graph_nodes_edges.pkl')
    # nodes, edges = load_data(nodes_edges_path)

    nodes = {
    "n1":  {'labels': ':AddedValue', 
            'id': 'org.wso2.carbon.apimgt:forum:6.5.275:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
            },
    "n2": {'labels': ':AddedValue', 
           'id': 'org.wso2.carbon.apimgt:forum:6.5.276:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
           },
    "n3": {'labels': ':AddedValue', 'id': 'org.wso2.carbon.apimgt:forum:6.5.272:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
           },
    "n4": {'labels': ':AddedValue', 'id': 'org.wso2.carbon.apimgt:forum:6.5.279:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'},
    "n5": {'labels': ':AddedValue', 'id': 'org.wso2.carbon.apimgt:forum:6.5.278:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'},
    "n6": {'labels': ':AddedValue', 'value': '1', 'id': 'io.gravitee.common:gravitee-common:3.1.0:POPULARITY_1_YEAR', 'type': 'POPULARITY_1_YEAR'},
    "n7": {'labels': ':AddedValue', 'value': '2', 'id': 'org.thepalaceproject.audiobook:org.librarysimplified.audiobook.parser.api:11.0.0:POPULARITY_1_YEAR', 'type': 'POPULARITY_1_YEAR'},
    "n8": {'labels': ':AddedValue', 'value': '1', 'id': 'com.emergetools.snapshots:snapshots-shared:0.8.1:POPULARITY_1_YEAR', 'type': 'POPULARITY_1_YEAR'},
    "n9": {'labels': ':AddedValue', 'id': 'se.fortnox.reactivewizard:reactivewizard-jaxrs:SPEED', 'type': 'SPEED', 'value': '0.08070175438596491'},
    "n10":{'labels': ':AddedValue', 'id': 'cc.akkaha:asura-dubbo_2.12:SPEED', 'type': 'SPEED', 'value': '0.029411764705882353'},
    "n11":{'labels': ':AddedValue', 'id': 'it.tidalwave.thesefoolishthings:it-tidalwave-thesefoolishthings-examples-dci-swing:SPEED', 'type': 'SPEED', 'value': '0.014814814814814815'},
    "n12":{'labels': ':AddedValue', 'id': 'com.softwaremill.sttp.client:core_sjs0.6_2.13:2.0.2:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"7\\",\\"outdatedTimeInMs\\":\\"3795765000\\"}}'},
    "n13":{'labels': ':AddedValue', 'id': 'com.ibeetl:act-sample:3.0.0-M6:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"2\\",\\"outdatedTimeInMs\\":\\"11941344000\\"}}'},
    "n14":{'labels': ':AddedValue', 'id': 'com.softwaremill.sttp.client:core_sjs0.6_2.13:2.0.0:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"9\\",\\"outdatedTimeInMs\\":\\"4685281000\\"}}'},
    "n15":{'labels': ':AddedValue', 'id': 'com.lihaoyi:ammonite_2.12.1:0.9.8:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"367\\",\\"outdatedTimeInMs\\":\\"142773884000\\"}}'},
    "n0":{'labels': ':AddedValue', 'id': 'com.yahoo.vespa:container-disc:7.394.21:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"448\\",\\"outdatedTimeInMs\\":\\"105191360000\\"}}'},
    'n16': {'labels': ':Release', 'id': 'org.wso2.carbon.identity.framework:org.wso2.carbon.identity.cors.mgt.core:5.20.111', 'version': '5.20.111', 'timestamp': '1626148242000'},
    'n17': {'labels': ':Release', 'id': 'org.apache.camel.quarkus:camel-quarkus-kotlin-parent:1.0.0-M4', 'version': '1.0.0-M4', 'timestamp': '1583239943000'},
    'n18': {'labels': ':Release', 'id': 'org.apache.camel.quarkus:camel-quarkus-kotlin-parent:1.0.0-M3', 'version': '1.0.0-M3', 'timestamp': '1579861029000'},
    'n19': {'labels': ':Release', 'id': 'org.wso2.carbon.identity.framework:org.wso2.carbon.identity.cors.mgt.core:5.20.113', 'version': '5.20.113', 'timestamp': '1626179580000'},
    'n20': {'labels': ':Release', 'id': 'org.wso2.carbon.identity.framework:org.wso2.carbon.identity.cors.mgt.core:5.20.112', 'version': '5.20.112', 'timestamp': '1626170945000'},
    'n21': {'labels': ':Release', 'id': 'org.wso2.carbon.identity.framework:org.wso2.carbon.identity.cors.mgt.core:5.20.115', 'version': '5.20.115', 'timestamp': '1626340086000'},
    'n22': {'labels': ':Release', 'id': 'org.apache.camel.quarkus:camel-quarkus-kotlin-parent:1.0.0-M2', 'version': '1.0.0-M2', 'timestamp': '1576600059000'},
    'n23': {'labels': ':Release', 'id': 'org.apache.camel.quarkus:camel-quarkus-kotlin-parent:1.0.0-M6', 'version': '1.0.0-M6', 'timestamp': '1586476381000'},
    'n24': {'labels': ':Release', 'id': 'org.wso2.carbon.identity.framework:org.wso2.carbon.identity.cors.mgt.core:5.20.114', 'version': '5.20.114', 'timestamp': '1626266264000'},
    'n25': {'labels': ':Release', 'version': '0.5.0', 'timestamp': '1669329622000', 'id': 'com.splendo.kaluga:alerts-androidlib:0.5.0'},

    }


    # Example edges
    edges = [
        ("n1", "n2", {"label": "relationship_AR"}),
        ("n1", "n12", {"label": "relationship_AR"}),
        ("n5", "n3", {"label": "relationship_AR"}),
        ("n1", "n6", {"label": "relationship_AR"}),
        ("n7", "n3", {"label": "relationship_AR"}),
        ("n1", "n11", {"label": "relationship_AR"}),
        ("n8", "n3", {"label": "relationship_AR"}),
        ("n4", "n7", {"label": "dependency"}),
        ("n10", "n12", {"label": "relationship_AR"}),
        ("n5", "n13", {"label": "relationship_AR"}),
        ("n4", "n14", {"label": "relationship_AR"}),
        ("n13", "n0", {"label": "dependency"}),
        ("n10", "n15", {"label": "relationship_AR"}),
        ("n1", "n16", {"label": "dependency"}),
        ("n19", "n25", {"label": "relationship_AR"}),
        ("n5", "n21", {"label": "relationship_AR"}),
        ("n21", "n23", {"label": "relationship_AR"}),
        ("n19", "n24", {"label": "relationship_AR"}),
        ("n4", "n19", {"label": "relationship_AR"}),
    ]
    

    dep_graph_path = Path.cwd().parent.joinpath("data", "dep_graph.pkl")

    depgraph = DepGraph(nodes, edges)
    if not dep_graph_path.exists():
        release_to_software = depgraph.rel_to_soft()
        software_releases = depgraph.soft_to_rel(release_to_software)
        time_rangs = depgraph.time_ranges(software_releases)

        # get the filtered edges
        filter_edges = depgraph.filter_edges(software_releases)

        graph = depgraph.dep_graph_build_parallel(filter_edges, time_rangs)
        # save graph
        depgraph.graph_save(graph, dep_graph_path)
    else:
        G = depgraph.graph_load(dep_graph_path)