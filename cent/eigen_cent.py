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
        self.graph = {node: [] for node, attrs in nodes.items() if self.cve_check(attrs) or \
                      self.fresh_check(attrs) or self.popu_check(attrs) or self.speed_check(attrs)}
        # self.graph = {node: [] for node in nodes.keys()}

        # create the graph skeleton 
        # for source, target, _ in edges:
        #     # consider both incoming and outcoming edges for eigenvector
        #     if target in self.graph and source in self.graph:
        #         self.graph[target].append(source)
        #         self.graph[source].append(target)

        for source, target, _ in edges:
            # consider both incoming and outcoming edges for eigenvector
            if target in self.graph and source in self.graph:
                self.graph[target].append(source)
                self.graph[source].append(target)
    
    def str_to_json(self, escaped_json_str):
        try:
            clean_str = escaped_json_str.replace('\\"', '"')
            return json.loads(clean_str)
        except ValueError as e:
            print(f"Error parsing JSON: {e}")
            return None

    def popu_check(self, node: dict):
        if 'type' in node and node['type'] == "POPULARITY_1_YEAR" and node["value"] !='0':
            return True
        else:
            return False
    
    def speed_check(self, node: dict):
        if 'type' in node and node['type'] == "SPEED" and node["value"] !='0':
            return True
        else:
            return False
    
    def fresh_check(self, node: dict):
        if 'type' in node and node['type'] == "FRESHNESS" and self.str_to_json(node["value"])['freshness'] !={}:
            return True
        else:
            return False

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
                    # "id": node['id'],
                    'numberMissedRelease': numberMissedRelease,
                    "outdatedTimeInMs": outdatedTimeInMs
                }
            )
        # create a dataframe
        df = pd.DataFrame(processed_data)

        # Mark rows where both values are zero for setting freshness_score to 0 later
        df['is_zero_freshness'] = (df['numberMissedRelease'] == 0) & (df['outdatedTimeInMs'] == 0)

        # Apply min-max normalization only for non-zero rows
        df["Normalized_Missed"] = df.loc[~df['is_zero_freshness'], 'numberMissedRelease']
        df["Normalized_Outdated"] = df.loc[~df['is_zero_freshness'], 'outdatedTimeInMs']

        # Min-max normalization for non-zero freshness entries
        df.loc[~df['is_zero_freshness'], "Normalized_Missed"] = (
            (df['numberMissedRelease'] - df['numberMissedRelease'].min()) / 
            (df['numberMissedRelease'].max() - df['numberMissedRelease'].min())
        )

        df.loc[~df['is_zero_freshness'], "Normalized_Outdated"] = (
            (df['outdatedTimeInMs'] - df['outdatedTimeInMs'].min()) / 
            (df['outdatedTimeInMs'].max() - df['outdatedTimeInMs'].min())
        )

        # Define weights for freshness calculation
        w1, w2 = 0.5, 0.5

        # Calculate freshness score for non-zero freshness entries
        df['freshness_score'] = 0  # Initialize all scores to 0
        df.loc[~df['is_zero_freshness'], 'freshness_score'] = (
            w1 * df['Normalized_Missed'] + w2 * df['Normalized_Outdated']
        )

        # Map the freshness scores back to the original nodes
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
                 node["SPEED"] = float(node["value"])
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
                data["indegree"].append(G.in_degree(nid) if G.has_node(nid) else 0)
                data["degree"].append(G.degree(nid) if G.has_node(nid) else 0)

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
        y = self.node_attr_df["degree"].values
        
        best_features = []
        
        while init_features:
            best_feature = None
            for feature in init_features:
                features = best_features + [feature]

                X_train = self.node_attr_df[features]
                # add constant term for intercept
                X_train = sm.add_constant(X_train)
                # Drop rows where X_train or y contains NaN or inf values
                valid_idx = X_train.apply(lambda x: np.isfinite(x)).all(axis=1) & np.isfinite(y)
                X_train = X_train[valid_idx]
                y_valid = y[valid_idx]

                # Check if X_train and y are not empty after dropping invalid rows
                if X_train.size == 0 or y_valid.size == 0:
                    continue

                X_train = X_train.values

                try:
                    model = sm.OLS(y, X_train).fit()

                    # Check if the model includes more than just the constant
                    if len(model.pvalues) > 1:
                        # Get the p-value of the last added feature
                        p_value = model.pvalues[-1]
                        logger.info(f"The p-value for feature {feature} is: {p_value}")
                        
                        # Check if feature is significant
                        if p_value < reg_thres:
                            if best_feature is None or model.rsquared > best_feature[1]:
                                best_feature = (feature, model.rsquared)

                except Exception as e:
                    logger.warning(f"Failed to fit model for feature {feature}: {e}")


            if best_feature:
                best_features.append(best_feature[0])
                init_features.remove(best_feature[0])
            else:
                logger.warning("No significant features found for addition.")
                break  
        
        return best_features


    def _weight_ana(self, corr_thres=0.1, reg_thres=0.05):
        ''' combine correlation and step-wise regression
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
        centrality = nx.eigenvector_centrality(G, max_iter=100, tol=1e-06, weight="weight")

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
    "n1":  {'labels': ':AddedValue', 
            'id': 'org.wso2.carbon.apimgt:forum:6.5.275:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
            },
    "n2": {'labels': ':AddedValue', 
           'id': 'org.wso2.carbon.apimgt:forum:6.5.276:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
           },
    "n3": {'labels': ':AddedValue', 'id': 'org.wso2.carbon.apimgt:forum:6.5.272:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
           },
    "n4": {'labels': ':AddedValue', 'id': 'org.wso2.carbon.apimgt:forum:6.5.279:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'},
    "n5": {'labels': ':AddedValue', 'id': 'org.wso2.carbon.apimgt:forum:6.5.278:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'},
    "n6": {'labels': ':AddedValue', 'value': '1', 'id': 'io.gravitee.common:gravitee-common:3.1.0:POPULARITY_1_YEAR', 'type': 'POPULARITY_1_YEAR'},
    "n7": {'labels': ':AddedValue', 'value': '2', 'id': 'org.thepalaceproject.audiobook:org.librarysimplified.audiobook.parser.api:11.0.0:POPULARITY_1_YEAR', 'type': 'POPULARITY_1_YEAR'},
    "n8": {'labels': ':AddedValue', 'value': '1', 'id': 'com.emergetools.snapshots:snapshots-shared:0.8.1:POPULARITY_1_YEAR', 'type': 'POPULARITY_1_YEAR'},
    "n9": {'labels': ':AddedValue', 'id': 'se.fortnox.reactivewizard:reactivewizard-jaxrs:SPEED', 'type': 'SPEED', 'value': '0.08070175438596491'},
    "n10":{'labels': ':AddedValue', 'id': 'cc.akkaha:asura-dubbo_2.12:SPEED', 'type': 'SPEED', 'value': '0.029411764705882353'},
    "n11":{'labels': ':AddedValue', 'id': 'it.tidalwave.thesefoolishthings:it-tidalwave-thesefoolishthings-examples-dci-swing:SPEED', 'type': 'SPEED', 'value': '0.014814814814814815'},
    "n12":{'labels': ':AddedValue', 'id': 'com.softwaremill.sttp.client:core_sjs0.6_2.13:2.0.2:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"7\\",\\"outdatedTimeInMs\\":\\"3795765000\\"}}'},
    "n13":{'labels': ':AddedValue', 'id': 'com.ibeetl:act-sample:3.0.0-M6:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"2\\",\\"outdatedTimeInMs\\":\\"11941344000\\"}}'},
    "n14":{'labels': ':AddedValue', 'id': 'com.softwaremill.sttp.client:core_sjs0.6_2.13:2.0.0:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"9\\",\\"outdatedTimeInMs\\":\\"4685281000\\"}}'},
    "n15":{'labels': ':AddedValue', 'id': 'com.lihaoyi:ammonite_2.12.1:0.9.8:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"367\\",\\"outdatedTimeInMs\\":\\"142773884000\\"}}'},
    "n16":{'labels': ':AddedValue', 'id': 'com.yahoo.vespa:container-disc:7.394.21:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"448\\",\\"outdatedTimeInMs\\":\\"105191360000\\"}}'},
    }


    # Example edges
    edges = [
        ("n1", "n2", {"label": "relationship_AR"}),
        ("n1", "n12", {"label": "relationship_AR"}),
        ("n5", "n3", {"label": "relationship_AR"}),
        ("n1", "n6", {"label": "relationship_AR"}),
        ("n7", "n3", {"label": "relationship_AR"}),
        ("n1", "n11", {"label": "relationship_AR"}),
        ("n8", "n3", {"label": "relationship_AR"}),
        ("n4", "n7", {"label": "relationship_AR"}),
        ("n10", "n12", {"label": "relationship_AR"}),
        ("n5", "n13", {"label": "relationship_AR"}),
        ("n4", "n14", {"label": "relationship_AR"}),
        ("n13", "n16", {"label": "relationship_AR"}),
        ("n10", "n15", {"label": "relationship_AR"}),
    ]


    att_features = ["freshness", "popularity", "speed", "severity"]

    eigencenter = EigenCent(nodes, edges, att_features, sever_score_map)
    # process node attribute values to right format
    eigencenter._quan_attrs()
    eigencenter._covt_df()
    
    # eigencenter._step_wise_reg(0.05, att_features)
    # analyse processed attributes
    eigencenter._weight_ana()

    # get the eigen centrality
    # print(eigencenter.cal_weighted_eigen_cent())
    print(eigencenter.cal_weighted_eigen_cent_nx())