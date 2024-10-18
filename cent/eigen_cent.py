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
    def __init__(self,):
    
    def _sever_map(self, sev_score_map_dict):
    
    def _fresh_score(self,):



    def _quan_attrs(self,):
        ''' initialize quantify attributes of nodes
        
        '''

    def cal_weighted_eigen_cent(self, nodes, edges, max_iterations=100, tolerance=1e-6):
        '''
        
        '''



# normalize the freshness with min-max normalization
