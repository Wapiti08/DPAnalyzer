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
            "indegree": [],
            "degree": []
        }

        # create a direct graph
        G = nx.DiGraph()

        # Add edges based on your self.graph structure
        for node, neighbors in self.graph.items():
            for neighbor in neighbors:
                G.add_edge(node, neighbor)

        for nid, node in self.nodes.items():
            data["id"].append(nid)
            # replace dict freshness with freshness_score
            data["freshness"].append(node["freshness_score"])
            data["popularity"].append(node["POPULARITY_1_YEAR"])
            data["speed"].append(node["SPEED"])
            data["severity"].append(node["severity"])
            data["indegree"].append(int(G.in_degree(nid)))
            data["degree"].append(int(G.degree(nid)))

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
                numberMissedRelease = int(node["freshness"].get("numberMissedRelease", 0))
                outdatedTimeInMs = int(node["freshness"].get("outdatedTimeInMs", 0))
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
        df['Normalized_Outdated'] = (df['outdatedTimeInMs'] - df['outdatedTimeInMs'].min()) / \
                                    (df['outdatedTimeInMs'].max() - df['outdatedTimeInMs'].min())


        # define weights for freshness calculation
        w1, w2 = 0.5, 0.5

        # calculate freshness score
        df['freshness_score'] = w1 * df['Normalized_Missed'] + w2 * df['Normalized_Outdated']
    
        # map the freshness scores back to the original nodes
        for i, node in enumerate(self.nodes.values()):
            node["freshness_score"] = df.loc[i, 'freshness_score']
    
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
        attributes = ["freshness", "popularity", "speed", "severity"]
        X = self.node_attr_df[attributes]
        # y = self.node_attr_df["indegree"]
        y = self.node_attr_df["degree"]

        # return self.node_attr_df[attributes + ["indegree"]].corr()
        return self.node_attr_df[attributes + ["degree"]].corr()
        
    def _step_wise_reg(self, reg_thres, sele_features):
        ''' perform stepwise regression 
        
        '''
        init_features = self.node_attr_df[sele_features].columns.tolist()
        # y = self.node_attr_df["indegree"]
        y = self.node_attr_df["degree"]
        best_features = []

        while init_features:
            best_feature = None
            for feature in init_features:
                features = best_features + [feature]
                X_train = self.node_attr_df[features]
                # add constant term for intercept
                X_train = sm.add_constant(X_train)
                model = sm.OLS(y, X_train).fit()
                p_value = model.pvalues[feature]
                logger.info(f"the pvalues for feature {feature} is: {p_value}")
                # p_value is significant
                if p_value < reg_thres:
                    if best_feature is None or model.rsquared > best_feature[1]:
                        best_feature = (feature, model.rsquared)
            
            if best_feature:
                best_features.append(best_feature[0])
                init_features.remove(best_feature[0])
            else:
                break  
        
        return best_features


    def _weight_ana(self, corr_thres=0.1, reg_thres=0.05):
        ''' combine correlation analysis and step-wise regression
        to analyse different attributes with their contribution
        
        '''
        # perform correlation analysis for all features
        corr_results = self._corr_ana()
        print(corr_results)
        # sign_attrs = corr_results["indegree"].abs().where(lambda x: x>=corr_thres).dropna().index.tolist()
        sign_attrs = corr_results["degree"].abs().where(lambda x: x>=corr_thres).dropna().index.tolist()
        # sign_attrs.remove("indegree")
        sign_attrs.remove("degree")
        logger.info(f"Left important features after correlation analyis are: {sign_attrs}")

        # run step-wise regression using all features at once
        # self.node_attr_df = self.node_attr_df[sign_attrs + ["indegree"]]
        self.node_attr_df = self.node_attr_df[sign_attrs + ["degree"]]
        sele_features = self._step_wise_reg(reg_thres, sign_attrs)
        logger.info(f"Left important features after step-wise regression are: {sele_features}")


        # Step 3: Calculate contributions and aggregate into a single 'weight' attribute
        contribution_scores = {}
        total_contribution = 0

        for feature in sele_features:
            X_single = self.node_attr_df[[feature]]
            X_single = sm.add_constant(X_single)
            # model = sm.OLS(self.node_attr_df["indegree"], X_single).fit()
            model = sm.OLS(self.node_attr_df["degree"], X_single).fit()
            contribution = model.rsquared
            contribution_scores[feature] = contribution
            total_contribution += contribution

        # Step 4: Convert individual contributions into a combined weight attribute
        self.node_attr_df["weight"] = self.node_attr_df[sele_features].apply(
            lambda row: sum(row[feature] * (contribution_scores[feature] / total_contribution) for feature in sele_features),
            axis=1
        )

        # Step 5: Normalize the 'weight' to [0, 1] range
        min_weight = self.node_attr_df["weight"].min()
        max_weight = self.node_attr_df["weight"].max()
        if max_weight > min_weight:
            self.node_attr_df["weight"] = (self.node_attr_df["weight"] - min_weight) / (max_weight - min_weight)

        return self.node_attr_df[["weight"]]

    
    def _quan_attrs(self,):
        ''' initialize quantify attributes of nodes
        
        '''
        self._sever_map(sever_score_map)
        self._fresh_score()
        self._speed_proc()
        self._popu_proc()


    def cal_weighted_eigen_cent(self, max_iterations=100, tolerance=1e-6):
        ''' the attributes of original nodes have been quantified into numeric features as weight
        
        '''
        # Extract weights from the node attribute DataFrame
        weights = self.node_attr_df['weight'].to_dict()

        # initialize centrailities
        centrality = {node:0.0 for node in self.nodes.keys()}

        # update centrailities as per iteration
        for _ in range(max_iterations):
            new_centrality = {node: 0.0 for node in self.nodes.keys()}

            for node in self.nodes.keys():
                for neighbor in self.graph[node]:
                    new_centrality[node] += centrality[neighbor] * weights.get(neighbor, 0)
        
            # normalize the centralities
            norm = sum(new_centrality.values())    
            if norm == 0:
                break
            new_centrality = {node: val / norm for node, val in new_centrality.items()}
            
            # check for convergence
            if all(abs(new_centrality[node] - centrality[node]) < tolerance for node in self.nodes.keys()):
                break
        
            centrality = new_centrality
        # Sort the centralities and get the top 10
        top_cents = sorted(centrality.items(), key=lambda item: item[1], reverse=True)[:10]
    
        return top_cents
    

if __name__ == "__main__":
    # Example nodes with detailed attributes
    nodes = {
    "n1": {
        "labels": ":Artifact",
        "id": "com.example:core-utils",
        "found": "true",
        "severity": "HIGH",
        "freshness": {"numberMissedRelease": "3", "outdatedTimeInMs": "1000000000"},
        "POPULARITY_1_YEAR": 1200,
        "SPEED": 0.75
    },
    "n2": {
        "labels": ":Artifact",
        "id": "org.sample:logging-lib",
        "found": "false",
        "severity": "MODERATE",
        "freshness": {"numberMissedRelease": "2", "outdatedTimeInMs": "5000000000"},
        "POPULARITY_1_YEAR": 980,
        "SPEED": 0.90
    },
    "n3": {
        "labels": ":Artifact",
        "id": "com.app.feature:networking",
        "found": "true",
        "severity": "LOW",
        "freshness": {"numberMissedRelease": "7", "outdatedTimeInMs": "25000000000"},
        "POPULARITY_1_YEAR": 1100,
        "SPEED": 0.60
    },
    "n4": {
        "labels": ":Artifact",
        "id": "org.package:ui-components",
        "found": "false",
        "severity": "CRITICAL",
        "freshness": {"numberMissedRelease": "4", "outdatedTimeInMs": "18000000000"},
        "POPULARITY_1_YEAR": 1350,
        "speed": 0.82
    },
    "n5": {
        "labels": ":Artifact",
        "id": "io.module:analytics-core",
        "found": "true",
        "severity": "HIGH",
        "freshness": {"numberMissedRelease": "1", "outdatedTimeInMs": "2000000000"},
        "POPULARITY_1_YEAR": 1570,
        "SPEED": 0.95
    },
    "n6": {
        "labels": ":Artifact",
        "id": "com.system.library:security",
        "found": "true",
        "severity": "MODERATE",
        "freshness": {"numberMissedRelease": "6", "outdatedTimeInMs": "7000000000"},
        "POPULARITY_1_YEAR": 1440,
        "SPEED": 0.88
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
        "POPULARITY_1_YEAR": 1120,
        "SPEED": 0.80
    },
    "n9": {
        "labels": ":Artifact",
        "id": "org.utility:config",
        "found": "false",
        "severity": "CRITICAL",
        "freshness": {"numberMissedRelease": "3", "outdatedTimeInMs": "8500000000"},
        "POPULARITY_1_YEAR": 1550,
        "SPEED": 0.78
    },
    "n10": {
        "labels": ":Artifact",
        "id": "com.example.new:auth-lib",
        "found": "true",
        "severity": "MODERATE",
        "freshness": {"numberMissedRelease": "8", "outdatedTimeInMs": "12000000000"},
        "POPULARITY_1_YEAR": 1000,
        "speed": 0.70
    },
    "n11": {
        "labels": ":Artifact",
        "id": "com.newfeature.module:video-processor",
        "found": "true",
        "severity": "HIGH",
        "freshness": {"numberMissedRelease": "6", "outdatedTimeInMs": "16000000000"},
        "POPULARITY_1_YEAR": 1450,
        "SPEED": 0.86
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
        "POPULARITY_1_YEAR": 1025,
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
    # process node attribute values to right format
    eigencenter._quan_attrs()
    eigencenter._covt_df()
    
    eigencenter._step_wise_reg(0.05, att_features)
    # analyse processed attributes
    eigencenter._weight_ana()

    # get the eigen centrality
    print(eigencenter.cal_weighted_eigen_cent())