'''
 # @ Create Time: 2024-10-16 11:37:22
 # @ Modified time: 2024-10-16 11:37:25
 # @ Description: measure the eigenvector centrality, consider the influence 
 from node attributes like CVE (with severity, freshness, popularity, speed)

 original type of attributes:
    severity: string
    freshness: {
        "numberMissedRelease": str(int), ---- how many release have been missed
        "outdatedTimeInMs": str(timestamp) ---- outdated time
    }
    popularity: int
    speed: float
  
    '''

# define the mapping table from severity to score

sever_score_map = {
    "CRITICAL": 4,
    "HIGH":3, 
    "MODERATE":2,
    "LOW":1
}

class EigenCent:
    ''' calculate eigenvector centraility for directed graphs, only consider incoming edges
    
    '''
    def __init__(self, nodes, edges):
        self.nodes = nodes
        self.edges = edges

    
    def _sever_map(self, sev_score_map_dict):
    
    def _fresh_score(self,):

        
        # normalize the freshness with min-max normalization


    def _quan_attrs(self,):
        ''' initialize quantify attributes of nodes
        
        '''

    def cal_weighted_eigen_cent(self, nodes, edges, max_iterations=100, tolerance=1e-6):
        '''
        
        '''
        graph = {node: [] for node in nodes}
        weights = {node: float(attributes.get('weight', 1)) for node, attributes in edges.items()}

        for source, target, _ in edges:
            # only consider incoming edges for eigenvector
            graph[target].append(source)

        # initialize centrailities
        centrality = {node:0.0 for node in nodes}

        # update centrailities as per iteration
        for _ in range(max_iterations):
            new_centrality = {node: 0.0 for node in nodes}

            for node in nodes:
                for neighbor in graph[node]:
                    new_centrality[node] += centrality[neighbor] * weights[neighbor]
        
            # normalize the centralities
            norm = sum(new_centrality.values())    
            if norm == 0:
                break
            new_centrality = {node: val / norm for node, val in new_centrality.items()}
            
            # check for convergence
            if all(abs(new_centrality[node] - centrality[node]) < tolerance for node in nodes):
                break
        
            centrality = new_centrality

        return centrality
    

