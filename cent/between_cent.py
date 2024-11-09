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

    def bfs_shortest_paths(self, graph, start_node, min_severity_nodes=1):
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
        
        filtered_paths = {node: [p for p in paths[node] if self.has_severity(p, min_severity_nodes)] for node in paths}
        # filtered_paths = self.filter_paths(paths, keep_prop)

        return distances, filtered_paths
    

    def has_severity(self, path, min_count):
        # filter paths to remove thoes that don't meet the minimum severity requirement
        # count how many nodes in the path(excluding start/end) have severity
        
        seve_count = sum(1 for node in path[1:-1] if self.cve_check(self.nodes[node]))
        return seve_count >= min_count

    def cve_check(self, node:dict):
        if 'type' in node and node['type'] == "CVE" and self.str_to_json(node["value"])['cve'] !=[]:
            return True
        else:
            return False

    def filter_paths(self, paths, keep_prop):
        ''' Filters paths based on the presence of severity nodes, keeping a proportion of paths without severity. '''
        filtered = {}
        for node, path_list in paths.items():
            # Separate paths into those with and without severity
            with_severity = [p for p in path_list if any(self.cve_check(self.nodes[n]) for n in p[1:-1])]
            without_severity = [p for p in path_list if not any(self.cve_check(self.nodes[n]) for n in p[1:-1])]
            
            # Keep a proportion of the paths without severity
            to_keep_count = int(len(without_severity) * keep_prop)
            selected_without_severity = random.sample(without_severity, min(to_keep_count, len(without_severity)))

            # Combine filtered paths
            filtered[node] = with_severity + selected_without_severity
        
        return filtered


    def cal_between_cent(self, prop=0.5, max_iters=100, tolerance=1e-6):
    # def cal_between_cent(self, min_severity_nodes=1, max_iters=100, tolerance=1e-6):
        # create adj list and extract node weights, filtering only nodes with CVE info
        graph = {node_id: [] for node_id, node in self.nodes.items() if self.cve_check(node)}

        # graph = {node_id: [] for node_id in self.nodes.keys()}
        for source, target, _ in self.edges:
            if source in graph or target in graph:
                graph[source].append(target)
                # ignore the direction here
                graph[target].append(source)
        

        between_cent = {node: 0 for node in self.nodes}

        # iterate over all pairs of nodes and count shortest 
        # paths that pass through each node
        for start in graph:
            # _, paths = self.bfs_shortest_paths(graph, start, min_severity_nodes)
            _, paths = self.bfs_shortest_paths(graph, start, prop)

            for end in graph:
                if end != start and paths[end]:
                    total_paths = len(paths[end])
                    for path in paths[end]:
                        # exclude start and end nodes
                        for node in path[1:-1]:
                            between_cent[node] += 1 / total_paths

        # Sort nodes by centrality and return the top 10
        top_10 = sorted(between_cent.items(), key=lambda x: x[1], reverse=True)[:10]
        return top_10
    
    def cal_between_cent_seve_nx(self,):
        G = nx.DiGraph()

        # Step 1: Separate nodes into those with and without severity
        nodes_with_severity = {node_id: attrs for node_id, attrs in self.nodes.items() if self.cve_check(attrs)}

        # Step 2: Add nodes with severity to the graph
        for node_id, attrs in nodes_with_severity.items():
            G.add_node(node_id, **attrs)

        for source, target, edge_attrs in self.edges:
            if source in G or target in G:
                G.add_edge(source, target, **edge_attrs)

        # Step 6: Compute betweenness centrality for the filtered subgraph
        betweenness_scores = nx.betweenness_centrality(G)
        # Step 5: Print the betweenness centrality scores
        top_n = 10
        sorted_betweenness = sorted(betweenness_scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return sorted_betweenness


    def cal_between_cent_nx(self, proportion_without_severity=0.5):
        G = nx.DiGraph()

        # Step 1: Separate nodes into those with and without severity
        nodes_with_severity = {node_id: attrs for node_id, attrs in self.nodes.items() if self.cve_check(attrs)}
        nodes_without_severity = {node_id: attrs for node_id, attrs in self.nodes.items() if self.cve_check(attrs)}

        # Step 2: Add nodes with severity to the graph
        for node_id, attrs in nodes_with_severity.items():
            G.add_node(node_id, **attrs)

        # Step 3: Determine how many nodes without severity to include
        num_nodes_with_severity = len(nodes_with_severity)
        total_nodes_without_severity = len(nodes_without_severity)
        num_nodes_to_include = int(total_nodes_without_severity * proportion_without_severity)

        # Randomly select nodes without severity to include
        selected_without_severity = random.sample(list(nodes_without_severity.keys()), min(num_nodes_to_include, total_nodes_without_severity))

        # Step 4: Add the selected nodes without severity to the graph
        for node_id in selected_without_severity:
            G.add_node(node_id, **nodes_without_severity[node_id])

        # Step 5: Add edges
        for source, target, edge_attrs in self.edges:
            if source in G or target in G:
                G.add_edge(source, target, **edge_attrs)

        # Step 6: Compute betweenness centrality for the filtered subgraph
        betweenness_scores = nx.betweenness_centrality(G)
        # Step 5: Print the betweenness centrality scores
        top_n = 10
        sorted_betweenness = sorted(betweenness_scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return sorted_betweenness


if __name__ == "__main__":
    # Example nodes with detailed attributes
    nodes = {
    "n0": {'labels': ':AddedValue', 
         'id': 'org.keycloak:keycloak-core:3.4.1.Final:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-267]\\",\\"severity\\":\\"HIGH\\",\\"name\\":\\"CVE-2019-10170\\"},{\\"cwe\\":\\"[CWE-79]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2022-0225\\"},{\\"cwe\\":\\"[CWE-79]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2020-1697\\"},{\\"cwe\\":\\"[CWE-547,CWE-798]\\",\\"severity\\":\\"CRITICAL\\",\\"name\\":\\"CVE-2019-14837\\"},{\\"cwe\\":\\"[CWE-306]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2021-20262\\"},{\\"cwe\\":\\"[CWE-1021]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2020-1728\\"},{\\"cwe\\":\\"[CWE-285,CWE-287]\\",\\"severity\\":\\"HIGH\\",\\"name\\":\\"CVE-2018-14637\\"},{\\"cwe\\":\\"[CWE-276]\\",\\"severity\\":\\"LOW\\",\\"name\\":\\"UNKNOWN\\"},{\\"cwe\\":\\"[CWE-285]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2020-10686\\"},{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"HIGH\\",\\"name\\":\\"CVE-2020-1714\\"},{\\"cwe\\":\\"[CWE-287,CWE-841]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"UNKNOWN\\"},{\\"cwe\\":\\"[CWE-613]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2020-1724\\"},{\\"cwe\\":\\"[CWE-835]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2018-10912\\"},{\\"cwe\\":\\"[CWE-287]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2020-27838\\"},{\\"cwe\\":\\"[CWE-287,CWE-841]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-0105\\"},{\\"cwe\\":\\"[CWE-200,CWE-755]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2020-1744\\"},{\\"cwe\\":\\"[CWE-295,CWE-345]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2019-3875\\"},{\\"cwe\\":\\"[CWE-601]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"UNKNOWN\\"},{\\"cwe\\":\\"[CWE-200,CWE-532]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2020-1698\\"},{\\"cwe\\":\\"[CWE-863]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2022-1466\\"},{\\"cwe\\":\\"[CWE-200]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2019-14820\\"},{\\"cwe\\":\\"[CWE-295]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"UNKNOWN\\"},{\\"cwe\\":\\"[CWE-250]\\",\\"severity\\":\\"HIGH\\",\\"name\\":\\"CVE-2020-27826\\"},{\\"cwe\\":\\"[CWE-377]\\",\\"severity\\":\\"HIGH\\",\\"name\\":\\"CVE-2021-20202\\"},{\\"cwe\\":\\"[CWE-330,CWE-341]\\",\\"severity\\":\\"CRITICAL\\",\\"name\\":\\"CVE-2020-1731\\"},{\\"cwe\\":\\"[CWE-80]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2022-0225\\"},{\\"cwe\\":\\"[CWE-645]\\",\\"severity\\":\\"LOW\\",\\"name\\":\\"CVE-2024-1722\\"},{\\"cwe\\":\\"[CWE-200]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2019-3868\\"},{\\"cwe\\":\\"[CWE-287]\\",\\"severity\\":\\"HIGH\\",\\"name\\":\\"CVE-2021-3632\\"},{\\"cwe\\":\\"[CWE-295]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2020-35509\\"},{\\"cwe\\":\\"[CWE-79]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"UNKNOWN\\"},{\\"cwe\\":\\"[CWE-601,CWE-918]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2020-10770\\"},{\\"cwe\\":\\"[CWE-20,CWE-352]\\",\\"severity\\":\\"HIGH\\",\\"name\\":\\"CVE-2019-10199\\"},{\\"cwe\\":\\"[CWE-347]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2019-10201\\"},{\\"cwe\\":\\"[CWE-284,CWE-863]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-0091\\"},{\\"cwe\\":\\"[CWE-295]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-1664\\"},{\\"cwe\\":\\"[CWE-602]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2017-12161\\"},{\\"cwe\\":\\"[CWE-116,CWE-20,CWE-79]\\",\\"severity\\":\\"CRITICAL\\",\\"name\\":\\"CVE-2021-20195\\"},{\\"cwe\\":\\"[CWE-22,CWE-552]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2021-3856\\"},{\\"cwe\\":\\"[CWE-269,CWE-916]\\",\\"severity\\":\\"HIGH\\",\\"name\\":\\"CVE-2020-14389\\"},{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2021-3754\\"}]}'
         },
    "n1":  {'labels': ':AddedValue', 
            'id': 'org.wso2.carbon.apimgt:forum:6.5.275:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
            },
    "n2": {'labels': ':AddedValue', 
           'id': 'org.wso2.carbon.apimgt:forum:6.5.276:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
           },
    "n3": {'labels': ':AddedValue', 'id': 'org.wso2.carbon.apimgt:forum:6.5.272:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
           },
    }


    # Example edges
    edges = [
        ("n1", "n2", {"label": "relationship_AR"}),
        ("n1", "n3", {"label": "relationship_AR"}),
    ]

    betcenter = BetCent(nodes, edges)

    top_10 = betcenter.cal_between_cent_nx()
    print("top 10 with prop:",top_10)

    top_10 = betcenter.cal_between_cent_seve_nx()
    print("top 10 with min cve:",top_10)
    # results = {}
    # for prop in [0.1 * i for i in range(1, 10)]:
    #     top_10 = betcenter.cal_between_cent(prop=prop)
    #     # top_10 = betcenter.cal_between_cent()
    #     results[prop] = top_10
    
    # # Print results
    # for prop, top_10 in results.items():
    #     print(f"Proportion: {prop:.1f} | Top 10 Nodes: {top_10}")
    # print(betcenter.cal_between_cent())