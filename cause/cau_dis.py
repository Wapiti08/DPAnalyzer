'''
 # @ Create Time: 2024-10-15 15:57:35
 # @ Modified time: 2024-10-31 14:18:30
 # @ Description: causal discovery against the cve /cwe of nodes in dependency graph

 '''

import networkx as nx
import numpy as np
import pandas as pd
from pgmpy.estimators import PC
from sklearn.preprocessing import StandardScaler
from pgmpy.models import BayesianNetwork
from scipy.optimize import minimize
import json
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

class CauDiscover:
    
    def __init__(self, nodes, edges):
        self.nodes = nodes
        self.edges = edges
    
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

    def get_cve_nodes(self, ):
        return [node for node_id, node in self.nodes.items() if 'type' in node and \
                node['type'] == "CVE" and self.str_to_json(node["value"])['cve'] !=[]]

    def _data_create(self,):
        ''' create dataframe based on attribute info
        node, cve_exist, cve_score, cve_num
        
        return dataframe
        '''
        cve_features = {}
        cve_exists, cve_score, cve_num = 0,0,0
        
        for node_id, node in self.nodes:
            if self.cve_check(node):
                cve_exists = 1
                cve_list = self.str_to_json(node["value"])['cve']
                # get the string value in every list
                cve_seve_str_list = [cve["severity"] for cve in cve_list]
                # sum all the converted value
                cve_score_list = [self.severity_map.get(cve_str,0) for cve_str in cve_seve_str_list]
                cve_score = sum(cve_score_list)
                cve_num = len(cve_score_list)
            cve_features[node_id] = {
                "cve_exists": cve_exists,
                "cve_score": cve_score,
                "cve_num": cve_num
            }
        return pd.DataFrame.from_dict(cve_features, orient="index")

            
                


    def prune_cve_edges(self, data_df, sign_level=0.05):
        ''' prune edges among CVE nodes using conditional independence tests
        
        '''
        # consider nodes with CVEs
        cve_nodes = self.get_cve_nodes()
        cve_data = data_df[data_df['node'].isin(cve_nodes)].set_index('node')

        # apply the PC algorithm    
        pc = PC(cve_data)
        skeleton = pc.estimate(return_type="skeleton")

        # add edges that passed independence tests to a new graph
        pruned_G = nx.DiGraph()
        pruned_G.add_nodes_from(cve_nodes)

        for u, v in skeleton.edges():
            pruned_G.add_edge(u, v)
        
        return pruned_G

    def score_cve_graph(self, pruned_G, cve_data):
        ''' apply score-based learning using Bayesian Information Criterion (BIC) 
        to refine the causal structure among CVE nodes 
        
        '''
        model = BayesianNetwork(pruned_G.edges)
        model.fit(cve_data)
        bic_score = model.bic_score(cve_data)
        return bic_score

    def das_dis_cve(self, data, sign_level=0.05):

        # filter only CVE-related nodes and prune edges
        pruned_G = self.prune_cve_edges(data, sign_level)

        # score the pruned graph structure
        bic_score = self.score_cve_graph(pruned_G, data)
        logger.info(f"BIC score of pruned graph: {bic_score}")

        return pruned_G

    def causal_chain_length(self, caugraph):
        ''' compute the longest and shorest vul propagation lengths within causal graph 
        
        '''
        # compute all the shortest paths between nodes
        shortest_paths = dict(nx.all_pairs_shortest_path_length(caugraph))

        # compute longest causal chain
        max_length = 0
        longest_chain = None
        for source, paths in shortest_paths.items():
            for target, length in paths.items():
                if length > max_length:
                    max_length = length
                    longest_chain = nx.shortest_path(caugraph, source=source, target=target)

        logger.info(f"The longest length of causal chain is: {max_length}")
        logger.info(f"The longest chain is: {longest_chain}")
    
        return shortest_paths, longest_chain

    def _get_sum_severity(self, node):
        ''' convert severity string to numeric value and sum all severities
        
        return sum_cve_score, cve_nums
        '''
        # get the list
        if self.cve_check(node):
            cve_list = self.str_to_json(node["value"])['cve']
        else:
            return 0, 0
        # get the string value in every list
        cve_seve_str_list = [cve["severity"] for cve in cve_list]
        # sum all the converted value
        cve_score_list = [self.severity_map.get(cve_str,0) for cve_str in cve_seve_str_list]
        sum_seve_score = sum(cve_score_list)
        return sum_seve_score, len(cve_score_list)


    # filter the nodes with CVEs
    def build_cve_metrics(self, ):
        ''' build matrix including nodes with cve info
        
        '''
        features = []

        for node_id, node in self.nodes:
            # calculate the cve information
            sum_cve_score, cve_list = self._get_sum_severity(node)
            cve_info = [
            # whether exist
                int(self.cve_check(node)),
            # sum of cve score
                sum_cve_score,
            # number of cve
                len(cve_list)
            ]

            features.append(cve_info)
        
        scaler = StandardScaler()
        return scaler.fit_transform(np.array(features))


    def adj_matrix_build(self,):
        num_nodes = len(self.nodes)
        adj_matrix = np.zeros((num_nodes, num_nodes), dtype=int)
        for u, v, attr in self.edges:
            adj_matrix[u, v] = 1
        
        return adj_matrix
    
    def causal_score(self, params, adj_matrix, feature_matrix):
        num_nodes = adj_matrix.shape[0]
        score = 0.0
        for i in range(num_nodes):
            for j in range(num_nodes):
                if adj_matrix[i,j] == 1:
                    feature_diff = np.abs(feature_matrix[i] - feature_matrix[j])
                    score += np.dot(params, feature_diff)

        return -score


if __name__ == "__main__":
