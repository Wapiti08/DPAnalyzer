'''
 # @ Create Time: 2024-10-15 15:57:35
 # @ Modified time: 2024-10-31 14:18:30
 # @ Description: causal discovery against the cve /cwe of nodes in dependency graph


 '''

import networkx as nx
import numpy as np
import dask.dataframe as dd
from pgmpy.estimators import PC
from sklearn.preprocessing import StandardScaler
from pgmpy.models import BayesianNetwork
from pgmpy.estimators import BicScore
import json
import logging
import pickle
from pathlib import Path
from scipy.sparse import csr_matrix
import re
import pandas as pd
from collections import defaultdict


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('cau_dis.log')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

sever_score_map = {
    "CRITICAL": 4,
    "HIGH":3, 
    "MODERATE":2,
    "LOW":1
}

class CauDiscover:
    
    def __init__(self, nodes, edges, sever_score_map):
        self.nodes = nodes
        self.edges = edges
        self.severity_map = sever_score_map
        self.get_addvalue_edges()

    def get_timestamp(self, target:str):
        node = self.nodes[target]
        if "timestamp" in node:
            return int(node["timestamp"])
        else:
            return 0

    def str_to_json(self, escaped_json_str):
        try:
            clean_str = escaped_json_str.replace('\\"', '"')
            return json.loads(clean_str)
        except ValueError as e:
            print(f"Error parsing JSON: {e}")
            return None

    def get_addvalue_edges(self,):
        # source node is release, target node is addedvalue
        self.addvalue_dict = defaultdict(list)

        # Iterate over the edges and add the targets for each source where the label is 'addedValues'
        for source, target, edge_att in self.edges:
            if edge_att['label'] == "addedValues":
                self.addvalue_dict[source].append(target)

    def popu_check(self, target: str):
        # get attribute nodes
        node_list = self.addvalue_dict[target]
        for node_id in node_list:
            node = self.nodes[node_id]
            if node['type'] == "POPULARITY_1_YEAR":
                return True
            else:
                return False
    
    def speed_check(self, target: str):
        # get attribute nodes
        node_list = self.addvalue_dict[target]
        for node_id in node_list:
            node = self.nodes[node_id]
            if node['type'] == "SPEED":
                return True
            else:
                return False
    
    def fresh_check(self, target: str):
        # get attribute nodes
        node_list = self.addvalue_dict[target]
        for node_id in node_list:
            node = self.nodes[node_id]
            if node['type'] == "FRESHNESS":
                return True
            else:
                return False

    def cve_check(self, target:str):
        # get attribute nodes
        node_list = self.addvalue_dict[target]
        for node_id in node_list:
            node = self.nodes[node_id]
            if node['type'] == "CVE":
                return True
            else:
                return False

    def get_cve_nodes(self, ):
        return [node_id for node_id, node in self.nodes.items() if self.cve_check(node_id)]

    def nodes_with_attrs_check(self, node: str):
        if self.cve_check(node) or self.fresh_check(node) or self.popu_check(node) or \
            self.speed_check(node) or self.get_timestamp(node):
            return True
        else:
            return False 

    def nodes_with_attrs(self,):
        return [node_id for node_id, node in self.nodes.items() if self.nodes_with_attrs_check(node_id)]

    def find_two_hop_neighbors(self):
        '''Finds two-hop neighbors specifically between release nodes in a directed graph.'''
        release_to_release_neighbors = {}

        for source, target, edge_attr in self.edges:
            if self.nodes_with_attrs_check(source):
                # Track only relationships where both source and target create a release-to-release chain
                if self.nodes[source]['labels'] == ":Artifact" and edge_attr['label']=="relationship_AR":
                    # This is a release -> software edge; store the software's releases
                    software_releases = release_to_release_neighbors.get(target, set())
                    software_releases.add(source)
                    release_to_release_neighbors[target] = software_releases

                elif self.nodes[source]['labels'] == ':Release' and edge_attr['label']=="dependency":
                    # This is a software -> release edge; look for releases pointing to this software
                    if source in release_to_release_neighbors:
                        # Any existing releases pointing to this software form two-hop links
                        for release in release_to_release_neighbors[source]:
                            if release != target:  # Avoid self-loops
                                # Initialize set for the release if it doesn’t exist
                                if release not in release_to_release_neighbors:
                                    release_to_release_neighbors[release] = set()
                                release_to_release_neighbors[release].add(target)

        # Convert sets to lists for consistent output format
        return {node: list(neighbors) for node, neighbors in release_to_release_neighbors.items()}

    def _data_create_two_hop(self):
        '''Creates a DataFrame based on 2-hop neighbor relationships instead of direct edges.'''
        two_hop_neighbors = self.find_two_hop_neighbors()

        # Initialize lists for DataFrame columns
        node_ids, neighbor_ids = [], []
        node_cve_exists_list, neighbor_cve_exists_list = [], []
        node_cve_score_list, neighbor_cve_score_list = [], []
        node_cve_num_list, neighbor_cve_num_list = [], []
        time_list = []

        # Traverse 2-hop neighbors for each node
        for node, neighbors in two_hop_neighbors.items():

            # Initialize CVE attributes
            node_cve_exists, node_cve_score, node_cve_num = 0, 0, 0
            node_cve_list = []
            if self.cve_check(node):
                node_cve_exists = 1
                node_list = self.addvalue_dict[node]
                for node_id in node_list:
                    node = self.nodes[node_id]  
                    node_value_dict = self.str_to_json(node["value"])
                    try:
                        node_cve_list.extend(node_value_dict['cve'])
                    except:
                        continue                
                node_cve_score = sum([self.severity_map.get(cve["severity"], 0) for cve in node_cve_list])
                node_cve_num = len(node_cve_list)

            # Traverse each 2-hop neighbor
            for neighbor in neighbors:
                neighbor_cve_exists, neighbor_cve_score, neighbor_cve_num = 0, 0, 0

                neighbor_cve_list = []
                if self.cve_check(neighbor):
                    neighbor_cve_exists = 1
                    node_list = self.addvalue_dict[neighbor]
                    for node_id in node_list:
                        node = self.nodes[node_id]  
                        node_value_dict = self.str_to_json(node["value"])
                        try:
                            neighbor_cve_list.extend(node_value_dict['cve'])
                        except:
                            continue
                    neighbor_cve_score = sum([self.severity_map.get(cve["severity"], 0) for cve in neighbor_cve_list])
                    neighbor_cve_num = len(neighbor_cve_list)

                # Append data for each (node, neighbor) pair
                node_ids.append(node)
                neighbor_ids.append(neighbor)
                node_cve_exists_list.append(node_cve_exists)
                node_cve_score_list.append(node_cve_score)
                node_cve_num_list.append(node_cve_num)
                neighbor_cve_exists_list.append(neighbor_cve_exists)
                neighbor_cve_score_list.append(neighbor_cve_score)
                neighbor_cve_num_list.append(neighbor_cve_num)
                time_list.append(self.get_timestamp(neighbor))

        # Create a Dask DataFrame
        cve_features = {
            "source": node_ids,
            "target": neighbor_ids,
            "node_cve_exists": node_cve_exists_list,
            "node_cve_score": node_cve_score_list,
            "node_cve_num": node_cve_num_list,
            "neighbor_cve_exists": neighbor_cve_exists_list,
            "neighbor_cve_score": neighbor_cve_score_list,
            "neighbor_cve_num": neighbor_cve_num_list,
            "timestamp": time_list,
        }
        df = dd.from_pandas(pd.DataFrame(cve_features), npartitions=4)

        return df


    def _data_create(self,):
        ''' create dataframe based on attribute info

            source, target, source_cve_exists, source_cve_score, source_cve_num, 
            target_cve_exists, target_cve_score, target_cve_num, timestamp of targets,

        return dataframe
        '''
        # Initialize empty lists for each column
        source_cve_exists_list, target_cve_exists_list = [], []
        source_cve_score_list, target_cve_score_list = [], []
        source_cve_num_list, target_cve_num_list = [], []
        source_node_ids, target_node_ids = [], []  # Store the node ids for indexing
        time_list = []

        for source, target, _ in self.edges:
            source_cve_exists, source_cve_score, source_cve_num = 0, 0, 0  # Default values
            target_cve_exists, target_cve_score, target_cve_num = 0, 0, 0
            source_cve_list, target_cve_list = [], []
            if self.cve_check(source):
                source_cve_exists = 1
                node_list = self.addvalue_dict[source]
                for node_id in node_list:
                    node = self.nodes[node_id]  
                    node_value_dict = self.str_to_json(node["value"])
                    try:
                        source_cve_list.extend(node_value_dict['cve'])
                    except:
                        continue

                # Get the severity string for each CVE
                source_cve_seve_str_list = [cve["severity"] for cve in source_cve_list]
                # Convert each severity string to a score and sum them up
                source_cve_score = sum([self.severity_map.get(cve_str, 0) for cve_str in source_cve_seve_str_list])
                source_cve_num = len(source_cve_seve_str_list)

            # Append the data for this node
            source_node_ids.append(source)
            source_cve_exists_list.append(source_cve_exists)
            source_cve_score_list.append(source_cve_score)
            source_cve_num_list.append(source_cve_num)

            if self.cve_check(target):
                target_cve_exists = 1
                node_list = self.addvalue_dict[target]
                for node_id in node_list:
                    node = self.nodes[node_id]  
                    node_value_dict = self.str_to_json(node["value"])
                    try:
                        target_cve_list.extend(node_value_dict['cve'])
                    except:
                        continue
                # Get the severity string for each CVE
                target_cve_seve_str_list = [cve["severity"] for cve in target_cve_list]
                # Convert each severity string to a score and sum them up
                target_cve_score = sum([self.severity_map.get(cve_str, 0) for cve_str in target_cve_seve_str_list])
                target_cve_num = len(target_cve_seve_str_list)

            # Append the data for this node
            target_node_ids.append(target)
            target_cve_exists_list.append(target_cve_exists)
            target_cve_score_list.append(target_cve_score)
            target_cve_num_list.append(target_cve_num)

            # add timestamp if the value exists
            time_list.append(self.get_timestamp(target))

        # Create a Dask DataFrame where columns are features, and rows are node_ids
        cve_features = {
            "source": source_node_ids,
            "target": target_node_ids,
            "source_cve_exists": source_cve_exists_list,
            "source_cve_score": source_cve_score_list,
            "source_cve_num": source_cve_num_list,
            "target_cve_exists": target_cve_exists_list,
            "target_cve_score": target_cve_score_list,
            "target_cve_num": target_cve_num_list,
            "timestamp": time_list,
        }
        df = dd.from_pandas(pd.DataFrame(cve_features), npartitions=4)  # Use Dask DataFrame with 4 partitions
        
        return df

    def prune_cve_edges(self, data_df, sign_level=0.05):
        ''' prune edges among CVE nodes using conditional independence tests
        '''
        # consider nodes with CVEs
        nodes_with_attrs = self.nodes_with_attrs()
        cve_data = data_df.drop(columns = ["source", "target", 'timestamp'])
        # apply the PC algorithm    
        pc = PC(cve_data.compute())  
        skeleton = pc.estimate(significance_level=sign_level,return_type="skeleton")

        # add edges that passed independence tests to a new graph
        pruned_G = nx.DiGraph()
        pruned_G.add_nodes_from(nodes_with_attrs)

        # get the first element
        for u, v in skeleton[0].edges():
            pruned_G.add_edge(u, v)
        
        return pruned_G

    def score_cve_graph(self, pruned_G, cve_data):
        ''' apply score-based learning using Bayesian Information Criterion (BIC) 
        to refine the causal structure among CVE nodes 
        '''
        model = BayesianNetwork(pruned_G.edges)
        if isinstance(cve_data, dd.DataFrame):
            cve_data = cve_data.compute()
        model.fit(cve_data)
        bic = BicScore(cve_data)
        bic_score = bic.score(model)
        
        return bic_score

    def das_dis_cve(self, data, sign_level=0.05):
        
        # filter only CVE-related nodes and prune edges
        pruned_G = self.prune_cve_edges(data, sign_level)
        # score the pruned graph structure
        bic_score = self.score_cve_graph(pruned_G, data)
        logger.info(f"BIC score of pruned graph: {bic_score}")

        return pruned_G

    def causal_chain_length(self, caugraph):
        ''' compute the longest and shortest vul propagation lengths within causal graph 
        '''
        # compute all the shortest paths between nodes
        shortest_paths = dict(nx.all_pairs_shortest_path_length(caugraph))

        # compute longest causal chain
        max_length = 0
        longest_chain = None
        for source, paths in shortest_paths.items():
            for target, length in paths.items():
                if length > max_length:
                    max_length = length
                    longest_chain = nx.shortest_path(caugraph, source=source, target=target)

        logger.info(f"The longest length of causal chain is: {max_length}")
        logger.info(f"The longest chain is: {longest_chain}")
    
        return shortest_paths, longest_chain


    def unique_causal_paths(self, caugraph):
        '''
        Compute all unique causal paths within the causal graph and their counts.
        
        Args:
            caugraph: A NetworkX directed graph representing the causal graph.
        
        Returns:
            unique_paths_counts: A dictionary where keys are unique paths (as tuples of nodes) 
                                and values are the counts of these paths.
        '''
        from collections import defaultdict
        
        # Dictionary to store unique paths and their counts
        path_counts = defaultdict(int)
        
        # Iterate through all pairs of nodes in the graph
        for source in caugraph.nodes:
            for target in caugraph.nodes:
                if source != target:
                    # Find all simple paths from source to target
                    paths = list(nx.all_simple_paths(caugraph, source=source, target=target))
                    
                    # Convert each path to a tuple (hashable) and update its count
                    for path in paths:
                        path_tuple = tuple(path)
                        path_counts[path_tuple] += 1
        
        # Convert to a regular dictionary for cleaner output
        unique_paths_counts = dict(path_counts)
        print(unique_paths_counts)
        # Log results
        logger.info(f"Number of unique causal paths: {len(unique_paths_counts)}")
        for path, count in unique_paths_counts.items():
            logger.debug(f"Path: {path}, Count: {count}")
        
        return unique_paths_counts


def load_data(file_path):
    with file_path.open('rb') as f:
        data = pickle.load(f)
    return data['nodes'], data['edges']

if __name__ == "__main__":
    
    # file_path = Path.cwd().parent.joinpath("data", 'graph_nodes_edges.pkl')

    # # read nodes and edges
    # nodes, edges = load_data(file_path)

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


    edges = [
        ("n1", "n2", {"label": "relationship_AR"}),
        ("n1", "n12", {"label": "relationship_AR"}),
        ("n5", "n3", {"label": "relationship_AR"}),
        ("n1", "n6", {"label": "relationship_AR"}),
        ("n7", "n3", {"label": "relationship_AR"}),
        ("n1", "n11", {"label": "relationship_AR"}),
        ("n8", "n3", {"label": "relationship_AR"}),
        ("n4", "n7", {"label": "relationship_AR"}),
        ("n10", "n12", {"label": "relationship_AR"}),
        ("n5", "n13", {"label": "relationship_AR"}),
        ("n4", "n14", {"label": "relationship_AR"}),
        ("n13", "n0", {"label": "relationship_AR"}),
        ("n10", "n15", {"label": "relationship_AR"}),
        ("n1", "n16", {"label": "relationship_AR"}),
        ("n19", "n25", {"label": "relationship_AR"}),
        ("n5", "n21", {"label": "relationship_AR"}),
        ("n21", "n23", {"label": "relationship_AR"}),
        ("n19", "n24", {"label": "relationship_AR"}),
        ("n4", "n19", {"label": "relationship_AR"}),
    ]
    

    caudiscover = CauDiscover(nodes, edges, sever_score_map)

    cve_data_path = Path.cwd().parent.joinpath("data", 'cve_data.csv')

    if cve_data_path.exists():
        df = dd.read_csv(cve_data_path.as_posix())
    else:
        # prepare input from nodes and edges
        df = caudiscover._data_create()
        df.compute().to_csv(cve_data_path.as_posix(),index=False)

    
    # extrat the features part out of node
    # ------ discover at scale process ---------
    pruned_G = caudiscover.das_dis_cve(df)

    ## compute causal chain
    # shortest_paths, longest_chain = caudiscover.causal_chain_length(pruned_G)
    unique_paths_counts = caudiscover.unique_causal_paths(pruned_G)

    
    cve_siblings_data_path = Path.cwd().parent.joinpath("data", 'cve_2_siblings_data.csv')

    if cve_siblings_data_path.exists():
        sib_df = dd.read_csv(cve_siblings_data_path.as_posix())
    else:
        # prepare input from nodes and edges
        sib_df = caudiscover._data_create_two_hop()
        sib_df.compute().to_csv(cve_siblings_data_path.as_posix(),index=False)
            

    pruned_G = caudiscover.das_dis_cve(sib_df)
    unique_paths_counts = caudiscover.unique_causal_paths(pruned_G)
    
    # ----------- feature analysis ------------ 

    # compute cve metrics
    # feature_matrix = caudiscover.build_cve_metrics(df)

    # compute adjcency matrix
    # adj_matrix = caudiscover.adj_matrix_build()

    # num_features = 7
    # params = np.ones(num_features)
    # # compute causal score
    # cal_score = caudiscover.causal_score(params, feature_matrix)