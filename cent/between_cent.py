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
        distances = {start_node:0}
        paths = {start_node: [start_node]}
        queue = deque([start_node])

        while queue:
            # record current node and distance of current node
            current = queue.popleft()
            cur_dist = distances[current]

            for ngb in graph.get(current, []):
                if ngb not in distances:
                    distances[ngb] = cur_dist + 1
                    paths[ngb] = paths[current] + [ngb]
                    queue.append(ngb)
        
        return distances, paths
    
    def cal_between_cent(self, ):
        graph = {node: [] for node in self.nodes}
        for source, target, _ in self.edges:
            graph[source].append(target)
            graph[target].append(source)
        
        between_cent = {node: 0 for node in self.nodes}

        # iterate over all pairs of nodes and count shortest 
        # paths that pass through each node
        

