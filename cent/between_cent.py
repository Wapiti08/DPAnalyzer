'''
 # @ Create Time: 2024-10-16 11:42:14
 # @ Modified time: 2024-10-16 11:42:16
 # @ Description: consider the betweenness of vulnerability propagation 
 path and general betweenness centrality
 '''

import random
from collections import deque
import networkx as nx
import json


class BetCent:
    def __init__(self, nodes, edges):
        '''
        :param nodes: dict type, {node: attrs}, attrs is dict type
        :param edges: list type, element is like (n_i, n_j, {'label':xx})
        '''
        self.nodes = nodes
        self.edges = edges
    
    def str_to_json(self, escaped_json_str):
        try:
            clean_str = escaped_json_str.replace('\\"', '"')
            return json.loads(clean_str)
        except ValueError as e:
            print(f"Error parsing JSON: {e}")
            return None

    def bfs_shortest_paths(self, graph, start_node, ):
    # def bfs_shortest_paths(self, graph, start_node, keep_prop=0.5):
        ''' BFS to find shortest paths in a directed graph
        
        '''
        
        distances = {start_node:0 for node in graph}
        # track all shorted paths to each node
        paths = {node: [] for node in graph}
        distances[start_node] = 0
        paths[start_node] = [[start_node]]

        queue = deque([start_node])

        while queue:
            # record current node and distance of current node
            node = queue.popleft()
            for ngb in graph[node]:
                if ngb not in distances:
                    distances[ngb] = distances[node] + 1
                    queue.append(ngb)
                    paths[ngb] = [path + [ngb] for path in paths[node]]
                elif distances[ngb] == distances[node] + 1:
                    # add more paths of the same shortest length
                    paths[ngb].extend([path + [ngb] for path in paths[node]]) 
        
        # filtered_paths = {node: [p for p in paths[node] if self.has_severity(p, min_severity_nodes)] for node in paths}
        # filtered_paths = self.filter_paths(paths, keep_prop)

        # return distances, filtered_paths
        return distances, paths
    
    def get_timestamp(self, node:dict):
        if "timestamp" in node:
            return int(node["timestamp"])
        else:
            return 0
        
    def has_severity(self, path, min_count):
        # filter paths to remove thoes that don't meet the minimum severity requirement
        # count how many nodes in the path(excluding start/end) have severity
        
        seve_count = sum(1 for node in path[1:-1] if self.cve_check(self.nodes[node]))
        return seve_count >= min_count

    def popu_check(self, node: dict):
        if 'type' in node and node['type'] == "POPULARITY_1_YEAR" and node["value"] !='0':
            return True
        else:
            return False
    
    def speed_check(self, node: dict):
        if 'type' in node and node['type'] == "SPEED" and node["value"] !='0':
            return True
        else:
            return False
    
    def fresh_check(self, node: dict):
        if 'type' in node and node['type'] == "FRESHNESS" and self.str_to_json(node["value"])['freshness'] !={}:
            return True
        else:
            return False

    def cve_check(self, node:dict):
        if 'type' in node and node['type'] == "CVE" and self.str_to_json(node["value"])['cve'] !=[]:
            return True
        else:
            return False

    # def filter_paths(self, paths, keep_prop):
    #     ''' Filters paths based on the presence of severity nodes, keeping a proportion of paths without severity. '''
    #     filtered = {}
    #     for node, path_list in paths.items():
    #         # Separate paths into those with and without severity
    #         with_severity = [p for p in path_list if any(self.cve_check(self.nodes[n]) for n in p[1:-1])]
    #         without_severity = [p for p in path_list if not any(self.cve_check(self.nodes[n]) for n in p[1:-1])]
            
    #         # Keep a proportion of the paths without severity
    #         to_keep_count = int(len(without_severity) * keep_prop)
    #         selected_without_severity = random.sample(without_severity, min(to_keep_count, len(without_severity)))

    #         # Combine filtered paths
    #         filtered[node] = with_severity + selected_without_severity
        
    #     return filtered


    # def cal_between_cent(self, prop=0.5, max_iters=100, tolerance=1e-6):
    # # def cal_between_cent(self, min_severity_nodes=1, max_iters=100, tolerance=1e-6):
    #     # create adj list and extract node weights, filtering only nodes with CVE info
    #     graph = {node_id: [] for node_id, node in self.nodes.items() if self.cve_check(node)}

    #     # graph = {node_id: [] for node_id in self.nodes.keys()}
    #     for source, target, _ in self.edges:
    #         if source in graph or target in graph:
    #             graph[source].append(target)
    #             # ignore the direction here
    #             graph[target].append(source)
        

    #     between_cent = {node: 0 for node in self.nodes}

    #     # iterate over all pairs of nodes and count shortest 
    #     # paths that pass through each node
    #     for start in graph:
    #         # _, paths = self.bfs_shortest_paths(graph, start, min_severity_nodes)
    #         _, paths = self.bfs_shortest_paths(graph, start, prop)

    #         for end in graph:
    #             if end != start and paths[end]:
    #                 total_paths = len(paths[end])
    #                 for path in paths[end]:
    #                     # exclude start and end nodes
    #                     for node in path[1:-1]:
    #                         between_cent[node] += 1 / total_paths

    #     # Sort nodes by centrality and return the top 10
    #     top_10 = sorted(between_cent.items(), key=lambda x: x[1], reverse=True)[:10]
    #     return top_10
    
    # def cal_between_cent_seve_nx(self,):
    #     G = nx.DiGraph()

    #     # Step 1: Separate nodes into those with and without severity
    #     nodes_with_severity = {node_id: attrs for node_id, attrs in self.nodes.items() if self.cve_check(attrs)}

    #     # Step 2: Add nodes with severity to the graph
    #     for node_id, attrs in nodes_with_severity.items():
    #         G.add_node(node_id, **attrs)

    #     for source, target, edge_attrs in self.edges:
    #         if source in G or target in G:
    #             G.add_edge(source, target, **edge_attrs)

    #     # Step 6: Compute betweenness centrality for the filtered subgraph
    #     betweenness_scores = nx.betweenness_centrality(G)
    #     # Step 5: Print the betweenness centrality scores
    #     top_n = 10
    #     sorted_betweenness = sorted(betweenness_scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
    #     return sorted_betweenness

    def cal_between_cent_nx(self,):
        G = nx.DiGraph()

        # Step 1: Separate nodes into those with and without severity
        nodes_with_attrs = {node_id: attrs for node_id, attrs in self.nodes.items() if \
                            self.cve_check(attrs) or self.popu_check(attrs) or self.speed_check(attrs) \
                                or self.fresh_check(attrs) or self.get_timestamp(attrs)}

        # Step 2: Add nodes with severity to the graph
        for node_id, attrs in nodes_with_attrs.items():
            G.add_node(node_id, **attrs)

        for source, target, edge_attrs in self.edges:
            if source in G or target in G:
                G.add_edge(source, target, **edge_attrs)

        # Step 6: Compute betweenness centrality
        betweenness_scores = nx.betweenness_centrality(G)
        # Step 5: Print the betweenness centrality scores
        top_n = 10
        sorted_betweenness = sorted(betweenness_scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return sorted_betweenness

    # def cal_between_cent_nx(self, proportion_without_severity=0.5):
    #     G = nx.DiGraph()

    #     # Step 1: Separate nodes into those with and without severity
    #     nodes_with_severity = {node_id: attrs for node_id, attrs in self.nodes.items() if self.cve_check(attrs)}
    #     nodes_without_severity = {node_id: attrs for node_id, attrs in self.nodes.items() if self.cve_check(attrs)}

    #     # Step 2: Add nodes with severity to the graph
    #     for node_id, attrs in nodes_with_severity.items():
    #         G.add_node(node_id, **attrs)

    #     # Step 3: Determine how many nodes without severity to include
    #     num_nodes_with_severity = len(nodes_with_severity)
    #     total_nodes_without_severity = len(nodes_without_severity)
    #     num_nodes_to_include = int(total_nodes_without_severity * proportion_without_severity)

    #     # Randomly select nodes without severity to include
    #     selected_without_severity = random.sample(list(nodes_without_severity.keys()), min(num_nodes_to_include, total_nodes_without_severity))

    #     # Step 4: Add the selected nodes without severity to the graph
    #     for node_id in selected_without_severity:
    #         G.add_node(node_id, **nodes_without_severity[node_id])

    #     # Step 5: Add edges
    #     for source, target, edge_attrs in self.edges:
    #         if source in G or target in G:
    #             G.add_edge(source, target, **edge_attrs)

    #     # Step 6: Compute betweenness centrality for the filtered subgraph
    #     betweenness_scores = nx.betweenness_centrality(G)
    #     # Step 5: Print the betweenness centrality scores
    #     top_n = 10
    #     sorted_betweenness = sorted(betweenness_scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
    #     return sorted_betweenness


if __name__ == "__main__":
    # Example nodes with detailed attributes
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

    betcenter = BetCent(nodes, edges)

    top_10 = betcenter.cal_between_cent_nx()
    print("top 10 with prop:",top_10)

    # top_10 = betcenter.cal_between_cent_seve_nx()
    # print("top 10 with min cve:",top_10)
    # results = {}
    # for prop in [0.1 * i for i in range(1, 10)]:
    #     top_10 = betcenter.cal_between_cent(prop=prop)
    #     # top_10 = betcenter.cal_between_cent()
    #     results[prop] = top_10
    
    # # Print results
    # for prop, top_10 in results.items():
    #     print(f"Proportion: {prop:.1f} | Top 10 Nodes: {top_10}")
    # print(betcenter.cal_between_cent())