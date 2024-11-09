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
import numpy as np
import json


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
    def __init__(self, nodes, edges, features:list, severity_map: dict):
        self.nodes = nodes
        self.edges = edges
        self.features = features
        self.severity_map = severity_map
        # Create the graph skeleton with nodes that have severity > 0
        self.graph = {node: [] for node, attrs in nodes.items() if self._get_sum_severity(attrs) > 0}
        # self.graph = {node: [] for node in nodes.keys()}

        # create the graph skeleton 
        # for source, target, _ in edges:
        #     # consider both incoming and outcoming edges for eigenvector
        #     if target in self.graph and source in self.graph:
        #         self.graph[target].append(source)
        #         self.graph[source].append(target)

        for source, target, _ in edges:
            # consider both incoming and outcoming edges for eigenvector
            # self.graph[target].append(source)
            self.graph[source].append(target)
    
    def str_to_json(self, escaped_json_str):
        try:
            clean_str = escaped_json_str.replace('\\"', '"')
            return json.loads(clean_str)
        except ValueError as e:
            print(f"Error parsing JSON: {e}")
            return None

    def cve_check(self, node:dict):
        if 'type' in node and node['type'] == "CVE" and self.str_to_json(node["value"])['cve'] !=[]:
            return True
        else:
            return False

    def _get_sum_severity(self, node):
        ''' convert severity string to numeric value and sum all severities
        
        '''
        # get the list
        if self.cve_check(node):
            cve_list = self.str_to_json(node["value"])['cve']
        else:
            return 0
        # get the string value in every list
        cve_seve_str_list = [cve["severity"] for cve in cve_list]
        # sum all the converted value
        sum_seve_score = sum([self.severity_map.get(cve_str,0) for cve_str in cve_seve_str_list])
        return sum_seve_score

    def _fresh_score(self,):
        ''' assume the attribute of freshness in nodes is a dict type
        
        use simple min-max normalization to scale the value into [0,1]
        '''
        # prepare a list to save processed node data
        processed_data = []

        # extract freshness values and handle missing cases
        for id, node in self.nodes.items():
            if 'type' in node and node['type'] == "FRESHNESS" and self.str_to_json(node["value"])['freshness'] !={}:
                # convert string to json
                node = self.str_to_json(node["value"])
                numberMissedRelease = int(node["freshness"]["numberMissedRelease"])
                outdatedTimeInMs = int(node["freshness"]["outdatedTimeInMs"])
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
            if 'type' in node and node['type'] == "POPULARITY_1_YEAR" and node["value"] !='0':
                node["POPULARITY_1_YEAR"] = int(node["value"])
            else:
                node["POPULARITY_1_YEAR"] = 0
        
    def _speed_proc(self,):
        ''' process potential missing popularity
        
        '''
        for id, node in self.nodes.items():
            if 'type' in node and node['type'] == "SPEED" and node["value"] !='0':
                 node["SPEED"] = int(node["value"])
            else:
                node["SPEED"] = 0
    
    def _quan_attrs(self,):
        ''' initialize quantify attributes of nodes
        
        '''
        self._fresh_score()
        self._speed_proc()
        self._popu_proc()

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
            if nid in self.graph:
                data["id"].append(nid)
                # replace dict freshness with freshness_score
                data["freshness"].append(node["freshness_score"])
                data["popularity"].append(node["POPULARITY_1_YEAR"])
                data["speed"].append(node["SPEED"])
                severity_value = self._get_sum_severity(node)
                data["severity"].append(severity_value)
                data["indegree"].append(G.in_degree(nid))
                data["degree"].append(G.degree(nid))

        self.node_attr_df = pd.DataFrame(data)
   

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
                # Drop rows where X_train or y contains NaN or inf values
                # valid_idx = X_train.apply(lambda x: np.isfinite(x)).all(axis=1) & np.isfinite(y)
                # X_train = X_train[valid_idx]
                # y_valid = y[valid_idx]

                # # Check if X_train and y are not empty after dropping invalid rows
                # if X_train.empty or y_valid.empty:
                #     continue

                X_train = np.asarray(X_train)
                y = np.asarray(y)

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
        # sign_attrs = corr_results["indegree"].abs().where(lambda x: x>=corr_thres).dropna().index.tolist()
        sign_attrs = corr_results["degree"].abs().where(lambda x: x>=corr_thres).dropna().index.tolist()
        # sign_attrs.remove("indegree")
        if "degree" in sign_attrs:
            sign_attrs.remove("degree")
    
        logger.info(f"Left important features after correlation analyis are: {sign_attrs}")

        # run step-wise regression using all features at once
        # df = self.node_attr_df[sign_attrs + ["indegree"]]
        # create a new separate framework
        df = self.node_attr_df[sign_attrs + ["degree"]]
        sele_features = self._step_wise_reg(reg_thres, sign_attrs)
        logger.info(f"Left important features after step-wise regression are: {sele_features}")


        # Step 3: Calculate contributions and aggregate into a single 'weight' attribute
        contribution_scores = {}
        total_contribution = 0

        for feature in sele_features:
            X_single = df[feature]
            X_single = sm.add_constant(X_single)
            # model = sm.OLS(self.node_attr_df["indegree"], X_single).fit()
            model = sm.OLS(df["degree"], X_single).fit()
            contribution = model.rsquared
            contribution_scores[feature] = contribution
            total_contribution += contribution

        # Step 4: Convert individual contributions into a combined weight attribute
        self.node_attr_df["weight"] = df[sele_features].apply(
            lambda row: sum(row[feature] * (contribution_scores[feature] / total_contribution) for feature in sele_features),
            axis=1
        )

        # Step 5: Normalize the 'weight' to [0, 1] range
        min_weight = self.node_attr_df["weight"].min()
        max_weight = self.node_attr_df["weight"].max()
        if max_weight > min_weight:
            self.node_attr_df["weight"] = (self.node_attr_df["weight"] - min_weight) / (max_weight - min_weight)

        return self.node_attr_df[["weight"]]

    def cal_weighted_eigen_cent_nx(self, ):
        G = nx.DiGraph()
        # Add nodes with custom weights as attributes
        for nid, node in self.nodes.items():
            weights = {nid: w for nid, w in self.node_attr_df.set_index("id")["weight"].to_dict().items() if nid in self.graph}
            G.add_node(nid, weight=weights)

        # Add edges for incoming relationships (directed)
        for source, target, _ in self.edges:
            if target in self.nodes and source in self.nodes:
                G.add_edge(source, target)

        # Calculate eigenvector centrality with weight
        centrality = nx.eigenvector_centrality(G, max_iter=1000, tol=1e-06, weight="weight")

        # Store top 10 nodes by centrality score
        top_cents = sorted(centrality.items(), key=lambda item: item[1], reverse=True)[:10]
        
        return top_cents


    def cal_weighted_eigen_cent(self, max_iterations=100, tolerance=1e-6):
        ''' the attributes of original nodes have been quantified into numeric features as weight
        
        '''
        # Extract weights only for nodes with severity > 0
        weights = {nid: w for nid, w in self.node_attr_df.set_index("id")["weight"].to_dict().items() if nid in self.graph}

        # Initialize centrality only for nodes in `self.graph`
        centrality = {node: 0.0 for node in self.graph.keys()}

        # update centrailities as per iteration
        for _ in range(max_iterations):
            new_centrality = {node: 0.0 for node in self.graph.keys()}

            for node in self.graph:
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


    att_features = ["freshness", "popularity", "speed", "severity"]

    eigencenter = EigenCent(nodes, edges, att_features, sever_score_map)
    # process node attribute values to right format
    eigencenter._quan_attrs()
    eigencenter._covt_df()
    
    eigencenter._step_wise_reg(0.05, att_features)
    # analyse processed attributes
    eigencenter._weight_ana()

    # get the eigen centrality
    # print(eigencenter.cal_weighted_eigen_cent())
    print(eigencenter.cal_weighted_eigen_cent_nx())