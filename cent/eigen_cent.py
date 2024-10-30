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
import logging


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('eigen_cent.log')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

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
    def __init__(self, nodes, edges, features:list):
        self.nodes = nodes
        self.edges = edges
        self.features = features
        self.graph = {node: [] for node in nodes.keys()}

        # create the graph skeleton 
        for source, target, _ in edges:
            # only consider incoming edges for eigenvector
            self.graph[target].append(source)

    def _covt_df(self,):
        ''' covert nodes to node based dataframe
        
        '''
        # create a dict to save iterative values 
        data = {
            "id": [],
            "freshness": [],
            "popularity": [],
            "speed": [],
            "severity": [],
            "indegree": []
        }

        # create a direct graph
        G = nx.DiGraph()

        # Add edges based on your self.graph structure
        for node, neighbors in self.graph.items():
            for neighbor in neighbors:
                G.add_edge(node, neighbor)

        for id, node in self.nodes.items():
            data.ip.append(id)
            data.freshness.append(node["freshness"])
            data.popularity.append(node["POPULARITY_1_YEAR"])
            data.speed.append(node["SPEED"])
            data.severity.append(node["severity"])
            data.degree.append(G.in_degree(node))

        self.node_attr_df = pd.DataFrame(data)

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
        ''' using pandas to perform correlation analysis between severity, freshness, 
        popularity, speed with node degree
        
        '''
        
        attributes = ["freshness", "POPULARITY_1_YEAR", "SPEED", "severity"]
        X = self.node_attr_df[attributes]
        y = self.node_attr_df["indegree"]

        return self.node_attr_df[attributes + ["indegree"]].corr()
        
    def _step_wise_reg(self, ):
        ''' perform stepwise regression 
        
        '''
        X = self.node_attr_df

        init_features = self.node_attr_df[self.features].to_list()
        y = self.node_attr_df["indegree"]
        best_features = []

        while init_features:
            best_feature = None
            for feature in init_features:
                features = best_features + [feature]
                X_train = X[features]
                # add constant term for intercept
                X_train = sm.add_constant(X_train)
                model = sm.OLS(y, X_train).fit()
                p_value = model.pvalues[feature]
                # p_value is significant
                if p_value < 0.05:
                    if best_feature is None or model.rsquared > best_feature[1]:
                        best_feature = (feature, model.rsquared)
            
            if best_feature:
                best_features.append(best_feature[0])
                init_features.remove(best_feature[0])
            else:
                break  
        
        return best_features


    def _weight_ana(self,):
        ''' combine correlation analysis and step-wise regression
        to analyse different attributes with their contribution
        
        '''
        for att in self.features:
            logger.info("\nAnalysing {att} with in degree\n")

            # correlation for current attributes
            corr = self.node_attr_df[[att, "indegree"]].corr().iloc[0,1]
            logger.info(f"Correlation between {att} and Degree: {corr}")

            # perform step-wise regression with only this attributes
            sele_feat_single = self._step_wise_reg(self.node_attr_df[[att]], \
                                                           self.node_attr_df["indegree"])
            
            # Perform regression with selected features
            X_single = self.node_attr_df[sele_feat_single]
            X_single = sm.add_constant(X_single)
            model_single = sm.OLS(self.node_attr_df["indegree"], X_single).fit()

            # Show results of the regression for this attribute
            logger.info(f"Stepwise Regression Result for {att}:")
            logger.info(model_single.summary())


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

    att_features = ["freshness", "popularity", "speed", "severity"]

    eigencenter = EigenCent(nodes, edges, att_features)
    eigencenter._covt_df()
    # process node attribute values to right format
    eigencenter._quan_attrs()
    
    # analyse processed attributes
    eigencenter._corr_ana()
    eigencenter._step_wise_reg()
    eigencenter._weight_ana()

    # get the eigen centrality
    eigencenter.cal_weighted_eigen_cent(nodes)