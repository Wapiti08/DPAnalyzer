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
import pandas as pd
import statsmodels.api as sm
import networkx as nx

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

        self.graph = {node: [] for node in nodes.keys()}

        # create the graph skeleton 
        for source, target, _ in edges:
            # only consider incoming edges for eigenvector
            self.graph[target].append(source)

    
    def _sever_map(self, sev_score_map_dict):
        ''' encode nodes cve severity to numeric features, replace original one
        
        '''
        for id, node in self.nodes.items():
            severity = node.get("severity", None)
            node['severity'] = sev_score_map_dict.get(severity, 0)

    
    def _fresh_score(self,):
        ''' assume the attribute of freshness in nodes is a dict type
        
        use simple min-max normalization to scale the value into [0,1]
        '''
        # prepare a list to save processed node data
        processed_data = []

        # extract freshness values and handle missing cases
        for id, node in self.nodes.items():
            if "freshness" in node:
                numberMissedRelease = node["freshness"].get("numberMissedRelease", 0)
                outdatedTimeInMs = node["freshness"].get("outdatedTimeInMs", 0)
            else:
                numberMissedRelease = 0
                outdatedTimeInMs = 0
            
            # add to processed data --- in order to implemented dataframe-orient manipulation
            processed_data.append(
                {
                    "id": node['id'],
                    'numberMissedRelease': numberMissedRelease,
                    "outdatedTimeInMs": outdatedTimeInMs
                }
            )
        
        # create a dataframe
        df = pd.DataFrame(processed_data)

        # normalize the attributes with min-max normalization
        df["Normalized_Missed"] = (df['numberMissedRelease'] - df["numberMissedRelease"].min()) / \
                                    (df['numberMissedRelease'].max() - df["numberMissedRelease"].min())

        # define weights for freshness calculation
        w1, w2 = 0.5, 0.5

        # calculate freshness score
        df['Freshness_Score'] = w1 * df['Normalized_Missed'] + w2 * df['Normalized_Outdated']
    
        # map the freshness scores back to the original nodes
        for i, node in enumerate(self.nodes.values()):
            if "freshness" not in node:
                node["freshness"] = df.loc[i, 'Freshness_Score']
    
    def _popu_proc(self,):
        ''' process potential missing popularity
        
        '''
        for id, node in self.nodes.items():
            node["POPULARITY_1_YEAR"] = node.get("POPULARITY_1_YEAR", 0)
        
    def _speed_proc(self,):
        ''' process potential missing popularity
        
        '''
        for id, node in self.nodes.items():
            node["SPEED"] = node.get("SPEED", 0)

    def _corr_ana(self,):
        ''' using pandas to perform correlation analysis between severity, freshness, popularity, 
        speed with node degree
        
        '''
        # create a dict to save iterative values 
        data = {
            "id": [],
            "freshness": [],
            "popularity": [],
            "speed": [],
            "severity": [],
            "degree": []
        }

        for id, node in self.nodes.items():
            data.ip.append(id)
            data.freshness.append(node["freshness"])
            data.popularity.append(node["POPULARITY_1_YEAR"])
            data.speed.append(node["SPEED"])
            data.severity.append(node["severity"])



        


    def _step_wise_reg(self, X, y):
        ''' perform stepwise regression 
        
        '''
        init_features = X.columns.tolist()
        best_features = []





    def _weight_ana(self,):
        ''' 
        
        '''



    def _quan_attrs(self,):
        ''' initialize quantify attributes of nodes
        
        '''
        self._sever_map(sever_score_map)
        self._fresh_score()
        self._speed_proc()
        self._popu_proc()



    def cal_weighted_eigen_cent(self, nodes,  max_iterations=100, tolerance=1e-6):
        ''' the attributes of original nodes have been quantified into numeric features as weight
        
        :param nodes: dict type
        '''
        weights = {node: float(attributes.get('weight', 1)) for node, attributes in nodes.items()}

        # initialize centrailities
        centrality = {node:0.0 for node in nodes}

        # update centrailities as per iteration
        for _ in range(max_iterations):
            new_centrality = {node: 0.0 for node in nodes}

            for node in nodes:
                for neighbor in self.graph[node]:
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
    

