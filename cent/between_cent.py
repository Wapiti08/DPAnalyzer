'''
 # @ Create Time: 2024-10-16 11:42:14
 # @ Modified time: 2024-10-16 11:42:16
 # @ Description: consider the betweenness of vulnerability propagation 
 path and general betweenness centrality
 '''

from collections import deque

class BetCent:
    def __init__(self, nodes, edges):
        '''
        :param nodes: dict type, {node: attrs}, attrs is dict type
        :param edges: list type, element is like (n_i, n_j, {'label':xx})
        '''
        self.nodes = nodes
        self.edges = edges
    
    def bfs_shortest_paths(self, graph, start_node):
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

        return distances, paths
    
    def cal_between_cent(self, max_iters=100, tolerance=1e-6):
        # create adj list and extract node weights
        graph = {node_id: [] for node_id, node in self.nodes.items()}
        for source, target, _ in self.edges:
            graph[source].append(target)
            # graph[target].append(source)
        
        between_cent = {node: 0 for node in self.nodes}

        # iterate over all pairs of nodes and count shortest 
        # paths that pass through each node
        for start in self.nodes.keys():
            _, paths = self.bfs_shortest_paths(graph, start)

            for end in self.nodes:
                if end != start and paths[end]:
                    total_paths = len(paths[end])
                    for path in paths[end]:
                        # exclude start and end nodes
                        for node in path[1:-1]:
                            between_cent[node] += 1 / total_paths

        # Sort nodes by centrality and return the top 10
        top_10 = sorted(between_cent.items(), key=lambda x: x[1], reverse=True)[:10]
        return top_10
    

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
        "severity": "LOW",
        "freshness": {"numberMissedRelease": "7", "outdatedTimeInMs": "25000000000"},
        "popularity": 1100,
        "speed": 0.60
    },
    "n4": {
        "labels": ":Artifact",
        "id": "org.package:ui-components",
        "found": "false",
        "severity": "CRITICAL",
        "freshness": {"numberMissedRelease": "4", "outdatedTimeInMs": "18000000000"},
        "popularity": 1350,
        "speed": 0.82
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
        "severity": "HIGH",
        "freshness": {"numberMissedRelease": "4", "outdatedTimeInMs": "15000000000"},
        "popularity": 1120,
        "speed": 0.80
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
        "severity": "HIGH",
        "freshness": {"numberMissedRelease": "6", "outdatedTimeInMs": "16000000000"},
        "popularity": 1450,
        "speed": 0.86
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
    print(betcenter.cal_between_cent())