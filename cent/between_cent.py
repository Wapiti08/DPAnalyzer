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
                if distances[ngb] == float("inf"):
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
            distances, paths = self.bfs_shortest_paths(graph, start)

            for end in self.nodes:
                if end != start and end in paths:
                    total_paths = len(paths[end])
                    for node in paths[end]:
                        if node != start and node != end:
                            between_cent[node] += 1 / total_paths

        return between_cent
    

if __name__ == "__main__":
    pass