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
from collections import defaultdict
from pathlib import Path
import pickle

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
        self.get_addvalue_edges()
        # consider nodes with all attributes
        self.graph = {node: [] for node, attrs in nodes.items() if self.cve_check(node) or \
                      self.fresh_check(node) or self.popu_check(node) or self.speed_check(node)}

        for source, target, _ in edges:
            if target in self.graph and source in self.graph:
                self.graph[source].append(target)
    
    def get_timestamp(self, target:str):
        node = self.nodes[target]
        if "timestamp" in node:
            return int(node["timestamp"])
        else:
            return 0
        
    def str_to_json(self, escaped_json_str):
        try:
            clean_str = escaped_json_str.replace('\\"', '"')
            return json.loads(clean_str)
        except ValueError as e:
            print(f"Error parsing JSON: {e}")
            return None

    def get_addvalue_edges(self,):
        # source node is release, target node is addedvalue
        self.addvalue_dict = defaultdict(list)

        # Iterate over the edges and add the targets for each source where the label is 'addedValues'
        for source, target, edge_att in self.edges:
            if edge_att['label'] == "addedValues":
                self.addvalue_dict[source].append(target)

    def popu_check(self, target: str):
        # get attribute nodes
        node_list = self.addvalue_dict[target]
        for node_id in node_list:
            node = self.nodes[node_id]
            if node['type'] == "POPULARITY_1_YEAR":
                print('after checking popu', node)
                return True
            else:
                return False
    
    def speed_check(self, target: str):
        # get attribute nodes
        node_list = self.addvalue_dict[target]
        for node_id in node_list:
            node = self.nodes[node_id]
            if node['type'] == "SPEED":
                return True
            else:
                return False
    
    def fresh_check(self, target: str):
        # get attribute nodes
        node_list = self.addvalue_dict[target]
        for node_id in node_list:
            node = self.nodes[node_id]
            if node['type'] == "FRESHNESS":
                return True
            else:
                return False

    def cve_check(self, target:str):
        # get attribute nodes
        node_list = self.addvalue_dict[target]
        for node_id in node_list:
            node = self.nodes[node_id]
            if node['type'] == "CVE":
                return True
            else:
                return False

    def _get_sum_severity(self, target:str):
        ''' convert severity string to numeric value and sum all severities
        
        '''
        # get the list
        cve_list = []
        if self.cve_check(target):
            node_list = self.addvalue_dict[target]
            for node_id in node_list:
                node = self.nodes[node_id]  
                node_value_dict = self.str_to_json(node["value"])
                try:
                    cve_list.extend(node_value_dict['cve'])
                except:
                    continue
                
        else:
            return 0
        # get the string value in every list
        cve_seve_str_list = [cve["severity"] for cve in cve_list]
        # sum all the converted value
        sum_seve_score = sum([self.severity_map.get(cve_str,0) for cve_str in cve_seve_str_list])
        return sum_seve_score

    def _quan_attrs(self,):
        ''' initialize quantify attributes of nodes
        
        '''
        for id, node in self.nodes.items():
            self.nodes[id]["popularity"] = 0
            self.nodes[id]["freshness_missrelease"] = 0
            self.nodes[id]["freshness_outdays"] = 0
            self.nodes[id]["speed"] = 0.0
            node_list = self.addvalue_dict[id]
            for node_id in node_list:
                node = self.nodes[node_id]
                if node['type'] == "POPULARITY_1_YEAR":
                    self.nodes[id]["popularity"] = int(node["value"])
                elif node['type'] == "FRESHNESS":
                    value_dict = self.str_to_json(node["value"])
                    self.nodes[id]['freshness_missrelease'] = int(value_dict["freshness"]["numberMissedRelease"])
                    self.nodes[id]['freshness_outdays'] = int(value_dict["freshness"]["outdatedTimeInMs"]) / (1000 * 60 * 60 * 24)  # Convert to days
                elif node['type'] == "SPEED":
                    self.nodes[id]["speed"] = float(node["value"])
        

    def _covt_df(self, fea_matrix_path: Path):
        ''' covert nodes to node based dataframe
        
        '''
        if fea_matrix_path.exists():
            self.node_attr_df = pd.read_csv(fea_matrix_path)
            
        else:
            # create a dict to save iterative values 
            data = {
                "id": [],
                "freshness_missrelease": [],
                "freshness_outdays": [],
                "popularity": [],
                "speed": [],
                "severity": [],
                "outdegree": [],
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
                    data["freshness_missrelease"].append(node.get("freshness_missrelease", 0))
                    data["freshness_outdays"].append(node.get("freshness_outdays", 0))
                    data["popularity"].append(node.get("popularity", 0))
                    data["speed"].append(node.get("speed", 0))
                    severity_value = self._get_sum_severity(nid)
                    data["severity"].append(severity_value)
                    data["outdegree"].append(G.out_degree(nid) if G.has_node(nid) else 0)
                    data["degree"].append(G.degree(nid) if G.has_node(nid) else 0)

            self.node_attr_df = pd.DataFrame(data)
            print(self.node_attr_df.isnull().sum())
            self.node_attr_df.to_csv(fea_matrix_path,index=False)


    def _corr_ana(self,):
        ''' using pandas to perform correlation analysis between severity, freshness, 
        popularity, speed with node degree
        
        '''
        attributes = ["freshness_missrelease", "freshness_outdays", "popularity", "speed", "severity"]
        X = self.node_attr_df[attributes]
        y = self.node_attr_df["outdegree"]

        return self.node_attr_df[attributes + ["outdegree"]].corr()
    

    def _step_wise_reg(self, reg_thres, sele_features):
        ''' perform stepwise regression 
        
        '''
        init_features = self.node_attr_df[sele_features].columns.tolist()
        y = self.node_attr_df["outdegree"].values
        # y = self.node_attr_df["degree"].values
        
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

    def ave_weight(self, scaling_factor=2776187):
        # return self.node_attr_df[attributes + ["degree"]].corr()
        # Attributes and target
        attributes = ["freshness_missrelease", "freshness_outdays", "popularity", "speed", "severity"]
        y = self.node_attr_df["outdegree"]
        X = self.node_attr_df[attributes]

        # Step 1: Calculate correlations with the target
        corr_values = X.corrwith(y).abs()  # Use absolute correlation values
        logger.info(f"Correlation values with 'outdegree': {corr_values.to_dict()}")

        # Step 2: Normalize correlation values to get weights
        total_corr = corr_values.sum()
        if total_corr == 0:
            logger.warning("All correlations are zero; defaulting to equal weights.")
            normalized_corr = pd.Series(1 / len(attributes), index=attributes)
        else:
            normalized_corr = corr_values / total_corr
        logger.info(f"Normalized attribute weights: {normalized_corr.to_dict()}")

        # Step 3: Compute weighted average for each node
        self.node_attr_df["weight"] = self.node_attr_df[attributes].apply(
            lambda row: sum(row[attr] * normalized_corr[attr] for attr in attributes),
            axis=1
        )

        # Step 4: Optionally normalize the 'weight' column to [0, 1]
        min_weight = self.node_attr_df["weight"].min()
        max_weight = self.node_attr_df["weight"].max()
        if max_weight > min_weight:
            self.node_attr_df["weight"] = (self.node_attr_df["weight"] - min_weight) / (max_weight - min_weight) * scaling_factor
        return self.node_attr_df[["weight"]]


    # def _weight_ana(self, corr_thres=0.1, reg_thres=0.05, scaling_factor=1000000):
    #     ''' combine correlation and step-wise regression
    #     to analyse different attributes with their contribution
        
    #     '''
    #     # perform correlation analysis for all features
    #     corr_results = self._corr_ana()
    #     logger.info(f"the correlation table is: {corr_results}")
    #     sign_attrs = corr_results["outdegree"].abs().where(lambda x: x>=corr_thres).dropna().index.tolist()

    #     if "outdegree" in sign_attrs:
    #         sign_attrs.remove("outdegree")
    
    #     logger.info(f"Left important features after correlation analyis are: {sign_attrs}")

    #     # run step-wise regression using all features at once
    #     df = self.node_attr_df[sign_attrs + ["outdegree"]]
    #     sele_features = self._step_wise_reg(reg_thres, sign_attrs)
    #     logger.info(f"Left important features after step-wise regression are: {sele_features}")


    #     # Step 3: Calculate contributions and aggregate into a single 'weight' attribute
    #     contribution_scores = {}
    #     total_contribution = 0

    #     for feature in sele_features:
    #         X_single = df[feature]
    #         X_single = sm.add_constant(X_single)
    #         model = sm.OLS(self.node_attr_df["outdegree"], X_single).fit()
    #         contribution = model.rsquared
    #         contribution_scores[feature] = contribution
    #         total_contribution += contribution

    #     # Step 4: Convert individual contributions into a combined weight attribute
    #     self.node_attr_df["weight"] = df[sele_features].apply(
    #         lambda row: sum(row[feature] * (contribution_scores[feature] / total_contribution) for feature in sele_features),
    #         axis=1
    #     )

    #     self.node_attr_df['weights'] = self.norm_weight(self.node_attr_df, scaling_factor)

    def _weight_ana(self,):
        ''' use correlation analysis to calculate node weight
        
        '''
        # perform correlation analysis for all features
        corr_results = self._corr_ana()
        logger.info(f"the correlation table is: {corr_results}")
    
        features = ["freshness_missrelease", "freshness_outdays", "popularity", "speed", "severity"]

        # Initialize a new column for the weight calculation
        self.node_attr_df["weight"] = 0.0
    
        # Iterate through each node in the dataframe
        for index, row in self.node_attr_df.iterrows():
            total_weight = 0.0
            
            # Loop through each pair of features
            for feature in features:
                # Check if both feature and its corresponding coefficient exist
                if feature in row:
                    # Multiply the corresponding feature value by its coefficient from the correlation table
                    # Assuming corr_results is a DataFrame or dictionary where correlation values are accessible
                    corr_value = corr_results.get(feature, {}).get(feature, 0)  # Get correlation coefficient for the feature
                    total_weight += row[feature] * corr_value
    
            # Set the computed weight for the current node
            self.node_attr_df.at[index, 'weight'] = total_weight

    def cal_weighted_eigen_cent_nx(self, ):
        
        # ensure self.graph is a directed graph
        if not isinstance(self.graph, nx.DiGraph):
            G = nx.DiGraph()

            for node in self.graph:
                G.add_node(node)

            for source, targets in self.graph.items():
                for target in targets:
                    G.add_edge(source, target)
                
        # set weights as attributes for nodes in self.graph
        weights = self.node_attr_df.set_index("id")["weight"].to_dict()
        # weights = self.node_attr_df.set_index('id')["severity"].to_dict()

        for nid in G.nodes:
            G.nodes[nid]['weight'] = weights.get(nid, 1)
            # G.nodes[nid]['weight'] = weights.get(nid, 0)

        for u, v in G.edges:
            source_weight = G.nodes[u].get('weight', 1)
            target_weight = G.nodes[v].get('weight', 1)
            G[u][v]['weight'] = source_weight * target_weight

            # Calculate eigenvector centrality with the modified edge weights
        try:
            centrality = nx.eigenvector_centrality(G, max_iter=1000, tol=1e-06, weight="weight")
        except nx.PowerIterationFailedConvergence:
            raise ValueError("Eigenvector centrality failed to converge")

        # Store top 10 nodes by centrality score
        top_cents = sorted(centrality.items(), key=lambda item: item[1], reverse=True)[:10]
        
        return top_cents



if __name__ == "__main__":

    graph_path = Path.cwd().parent.joinpath("data", 'graph_nodes_edges.pkl')

    with graph_path.open('rb') as f:
        data = pickle.load(f)
    nodes, edges = data['nodes'], data['edges']

    att_features = ["freshness", "popularity", "speed", "severity"]

    eigencenter = EigenCent(nodes, edges, att_features, sever_score_map)
    # process node attribute values to right format
    # eigencenter._quan_attrs()
    fea_matrix_path = Path.cwd().parent.joinpath("data", "fea_matrix.csv")
    eigencenter._covt_df(fea_matrix_path)
    
    # eigencenter._step_wise_reg(0.05, att_features)
    # analyse processed attributes
    eigencenter._weight_ana()
    # eigencenter.ave_weight()

    # get the eigen centrality
    # print(eigencenter.cal_weighted_eigen_cent())
    print(eigencenter.cal_weighted_eigen_cent_nx())