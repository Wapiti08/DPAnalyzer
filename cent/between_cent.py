'''
 # @ Create Time: 2024-10-16 11:42:14
 # @ Modified time: 2024-10-16 11:42:16
 # @ Description: consider the betweenness of vulnerability propagation 
 path and general betweenness centrality
 '''

import random
from collections import deque
import networkx as nx


class BetCent:
    def __init__(self, nodes, edges):
        '''
        :param nodes: dict type, {node: attrs}, attrs is dict type
        :param edges: list type, element is like (n_i, n_j, {'label':xx})
        '''
        self.nodes = nodes
        self.edges = edges
    
    # def bfs_shortest_paths(self, graph, start_node, min_severity_nodes=1):
    def bfs_shortest_paths(self, graph, start_node, keep_prop=0.5):
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
        filtered_paths = self.filter_paths(paths, keep_prop)

        return distances, filtered_paths
    

    def has_severity(self, path, min_count):
        # filter paths to remove thoes that don't meet the minimum severity requirement
        # count how many nodes in the path(excluding start/end) have severity
        seve_count = sum(1 for node in path[1:-1] if "severity" in self.nodes[node])
        return seve_count >= min_count


    def filter_paths(self, paths, keep_prop):
        ''' Filters paths based on the presence of severity nodes, keeping a proportion of paths without severity. '''
        filtered = {}
        for node, path_list in paths.items():
            # Separate paths into those with and without severity
            with_severity = [p for p in path_list if any("severity" in self.nodes[n] for n in p[1:-1])]
            without_severity = [p for p in path_list if not any("severity" in self.nodes[n] for n in p[1:-1])]
            
            # Keep a proportion of the paths without severity
            to_keep_count = int(len(without_severity) * keep_prop)
            selected_without_severity = random.sample(without_severity, min(to_keep_count, len(without_severity)))

            # Combine filtered paths
            filtered[node] = with_severity + selected_without_severity
        
        return filtered


    def cal_between_cent(self, prop=0.5, max_iters=100, tolerance=1e-6):
    # def cal_between_cent(self, min_severity_nodes=1, max_iters=100, tolerance=1e-6):
        # create adj list and extract node weights, filtering only nodes with CVE info
        graph = {node_id: [] for node_id, node in self.nodes.items() if "severity" in node}
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
    
    def cal_between_cent_nx(self, proportion_without_severity=0.5):
        G = nx.DiGraph()

        # Step 1: Separate nodes into those with and without severity
        nodes_with_severity = {node_id: attrs for node_id, attrs in self.nodes.items() if 'severity' in attrs}
        nodes_without_severity = {node_id: attrs for node_id, attrs in self.nodes.items() if 'severity' not in attrs}

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

    # def caL_between_cent_nx(self):

    #     G = nx.DiGraph()
    #     # G = nx.Graph()

    #     # Step 2: Add nodes (optional, networkx adds them automatically with edges)
    #     for node_id, attrs in nodes.items():
    #         G.add_node(node_id, **attrs)

    #     # Step 3: Add edges
    #     for source, target, edge_attrs in edges:
    #         G.add_edge(source, target, **edge_attrs)

    #     # Step 4: Filter nodes that have the "severity" attribute
    #     severity_nodes = [n for n, attrs in G.nodes(data=True) if 'severity' in attrs]

    #     # Step 5: Create a subgraph with only nodes that have severity
    #     severity_subgraph = G.subgraph(severity_nodes)

    #     # Step 6: Compute betweenness centrality for the filtered subgraph
    #     betweenness_scores = nx.betweenness_centrality(severity_subgraph)

    #     # Step 4: Compute betweenness centrality
    #     # betweenness_scores = nx.betweenness_centrality(G)

    #     # Step 5: Print the betweenness centrality scores
    #     top_n = 10
    #     sorted_betweenness = sorted(betweenness_scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
    #     return sorted_betweenness


if __name__ == "__main__":
    # Example nodes with detailed attributes
    nodes = {
    "n0": {
        "labels": ":Artifact",
        "id": "com.splendo.kaluga:alerts-androidlib",
        "found": "true",
        "severity": "CRITICAL",
        "freshness": {"numberMissedRelease": "5", "outdatedTimeInMs": "18691100000"},
        "popularity": 1500,
        "speed": 0.85
    },
    "n1": {
        "labels": ":Artifact",
        "id": "com.example:core-utils",
        "found": "true",
        "severity": "HIGH",
        "freshness": {"numberMissedRelease": "3", "outdatedTimeInMs": "1000000000"},
        "popularity": 1200,
        "speed": 0.75
    },
    "n2": {
        "labels": ":Artifact",
        "id": "org.sample:logging-lib",
        "found": "false",
        "severity": "MODERATE",
        "freshness": {"numberMissedRelease": "2", "outdatedTimeInMs": "5000000000"},
        "popularity": 980,
        "speed": 0.90
    },
    "n3": {
        "labels": ":Artifact",
        "id": "com.app.feature:networking",
        "found": "true",
    },
    "n4": {
        "labels": ":Artifact",
        "id": "org.package:ui-components",
        "found": "false",
    },
    "n5": {
        "labels": ":Artifact",
        "id": "io.module:analytics-core",
        "found": "true",
        "severity": "HIGH",
        "freshness": {"numberMissedRelease": "1", "outdatedTimeInMs": "2000000000"},
        "popularity": 1570,
        "speed": 0.95
    },
    "n6": {
        "labels": ":Artifact",
        "id": "com.system.library:security",
        "found": "true",
        "severity": "MODERATE",
        "freshness": {"numberMissedRelease": "6", "outdatedTimeInMs": "7000000000"},
        "popularity": 1440,
        "speed": 0.88
    },
    "n7": {
        "labels": ":Artifact",
        "id": "org.framework:database",
        "found": "false",
    },
    "n8": {
        "labels": ":Artifact",
        "id": "com.example.module:parser",
        "found": "true",
    },
    "n9": {
        "labels": ":Artifact",
        "id": "org.utility:config",
        "found": "false",
        "severity": "CRITICAL",
        "freshness": {"numberMissedRelease": "3", "outdatedTimeInMs": "8500000000"},
        "popularity": 1550,
        "speed": 0.78
    },
    "n10": {
        "labels": ":Artifact",
        "id": "com.example.new:auth-lib",
        "found": "true",
        "severity": "MODERATE",
        "freshness": {"numberMissedRelease": "8", "outdatedTimeInMs": "12000000000"},
        "popularity": 1000,
        "speed": 0.70
    },
    "n11": {
        "labels": ":Artifact",
        "id": "com.newfeature.module:video-processor",
        "found": "true",
    },
    "n12": {
        "labels": ":Artifact",
        "id": "org.temp.module:chat-lib",
        "found": "false",
    },
    "n13": {
        "labels": ":Artifact",
        "id": "com.future.module:audio-processor",
        "found": "false",
        "severity": "LOW",
        "freshness": None,
        "popularity": 1025,
        "speed": None
        }
    }



    # Example edges
    edges = [
        ("n1", "n2", {"label": "relationship_AR"}),
        ("n1", "n3", {"label": "relationship_AR"}),
        ("n2", "n4", {"label": "relationship_AR"}),
        ("n5", "n1", {"label": "relationship_AR"}),
        ("n5", "n6", {"label": "relationship_AR"}),
        ("n3", "n7", {"label": "relationship_AR"}),
        ("n8", "n9", {"label": "relationship_AR"}),
        ("n2", "n10", {"label": "relationship_AR"}),
        ("n10", "n11", {"label": "relationship_AR"}),
        ("n11", "n12", {"label": "relationship_AR"}),
        ("n7", "n13", {"label": "relationship_AR"}),
        ("n3", "n10", {"label": "relationship_AR"}),
        ("n12", "n13", {"label": "relationship_AR"}),
        ("n5", "n8", {"label": "relationship_AR"}),
    ]

    betcenter = BetCent(nodes, edges)

    top_10 = betcenter.caL_between_cent_nx()
    print(top_10)

    # results = {}
    # for prop in [0.1 * i for i in range(1, 10)]:
    #     top_10 = betcenter.cal_between_cent(prop=prop)
    #     # top_10 = betcenter.cal_between_cent()
    #     results[prop] = top_10
    
    # # Print results
    # for prop, top_10 in results.items():
    #     print(f"Proportion: {prop:.1f} | Top 10 Nodes: {top_10}")
    # print(betcenter.cal_between_cent())