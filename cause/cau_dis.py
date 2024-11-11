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
from pgmpy.estimators import BicScore
from scipy.optimize import minimize
import json
import logging
import pickle
from pathlib import Path
import re

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('cau_dis.log')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

sever_score_map = {
    "CRITICAL": 4,
    "HIGH":3, 
    "MODERATE":2,
    "LOW":1
}

class CauDiscover:
    
    def __init__(self, nodes, edges, sever_score_map):
        self.nodes = nodes
        self.edges = edges
        self.severity_map = sever_score_map
    
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
        return [node_id for node_id, node in self.nodes.items() if 'type' in node and \
                node['type'] == "CVE" and self.str_to_json(node["value"])['cve'] !=[]]

    def _data_create(self,):
        ''' create dataframe based on attribute info
        node, cve_exist, cve_score, cve_num
        
        return dataframe
        '''
        # Initialize empty lists for each column
        cve_exists_list = []
        cve_score_list = []
        cve_num_list = []
        node_ids = []  # Store the node ids for indexing
        
        for node_id, node in self.nodes.items():
            cve_exists, cve_score, cve_num = 0, 0, 0  # Default values
            
            if self.cve_check(node):
                cve_exists = 1
                cve_list = self.str_to_json(node["value"])['cve']
                # Get the severity string for each CVE
                cve_seve_str_list = [cve["severity"] for cve in cve_list]
                # Convert each severity string to a score and sum them up
                cve_score = sum([self.severity_map.get(cve_str, 0) for cve_str in cve_seve_str_list])
                cve_num = len(cve_seve_str_list)

            # Append the data for this node
            node_ids.append(node_id)
            cve_exists_list.append(cve_exists)
            cve_score_list.append(cve_score)
            cve_num_list.append(cve_num)
        
        # Create a DataFrame where columns are features, and rows are node_ids
        cve_features = {
            "node": node_ids,
            "cve_exists": cve_exists_list,
            "cve_score": cve_score_list,
            "cve_num": cve_num_list
        }
        
        df = pd.DataFrame(cve_features)
        return df


    def prune_cve_edges(self, data_df, sign_level=0.05):
        ''' prune edges among CVE nodes using conditional independence tests
        
        '''
        
        # consider nodes with CVEs
        cve_nodes = self.get_cve_nodes()
        cve_df = data_df[data_df['node'].isin(cve_nodes)].set_index('node')
        cve_data = cve_df[["cve_exists", "cve_score", "cve_num"]]
        # apply the PC algorithm    
        pc = PC(cve_data)
        skeleton = pc.estimate(return_type="skeleton")

        # add edges that passed independence tests to a new graph
        pruned_G = nx.DiGraph()
        pruned_G.add_nodes_from(cve_nodes)

        # get the first 
        for u, v in skeleton[0].edges():
            pruned_G.add_edge(u, v)
        
        return pruned_G

    def score_cve_graph(self, pruned_G, cve_data):
        ''' apply score-based learning using Bayesian Information Criterion (BIC) 
        to refine the causal structure among CVE nodes 
        
        '''
        model = BayesianNetwork(pruned_G.edges)
        model.fit(cve_data)
        bic = BicScore(cve_data)
        bic_score = bic.score(model)
        
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

        for node_id, node in self.nodes.items():
            # calculate the cve information
            sum_cve_score, cve_list_len = self._get_sum_severity(node)
            cve_info = [
            # whether exist
                int(self.cve_check(node)),
            # sum of cve score
                sum_cve_score,
            # number of cve
                cve_list_len
            ]

            features.append(cve_info)
        
        scaler = StandardScaler()
        return scaler.fit_transform(np.array(features))


    def adj_matrix_build(self,):
        num_nodes = len(self.nodes)
        adj_matrix = np.zeros((num_nodes, num_nodes), dtype=int)
        for u, v, attr in self.edges:
            u_index = int(re.search(r'\d+', u).group())
            v_index = int(re.search(r'\d+', v).group())
            adj_matrix[u_index, v_index] = 1
        
        return adj_matrix
    
    def causal_score(self, params, adj_matrix, feature_matrix):
        '''
        :param params: the set of weights for each feature
        
        '''
        num_nodes = adj_matrix.shape[0]
        score = 0.0
        for i in range(num_nodes):
            for j in range(num_nodes):
                if adj_matrix[i,j] == 1:
                    feature_diff = np.abs(feature_matrix[i] - feature_matrix[j])
                    score += np.dot(params, feature_diff)
        
        logger.info(f"the causal score computed from matrix is: {-score}")

        return -score


def load_data(file_path):
    with file_path.open('rb') as f:
        data = pickle.load(f)
    return data['nodes'], data['edges']



if __name__ == "__main__":
    
    file_path = Path.cwd().parent.joinpath("data", 'graph_nodes_edges.pkl')
    # read nodes and edges
    nodes, edges = load_data(file_path)

    # Example nodes with detailed attributes
    # nodes = {
    # "n1":  {'labels': ':AddedValue', 
    #         'id': 'org.wso2.carbon.apimgt:forum:6.5.275:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
    #         },
    # "n2": {'labels': ':AddedValue', 
    #        'id': 'org.wso2.carbon.apimgt:forum:6.5.276:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
    #        },
    # "n3": {'labels': ':AddedValue', 'id': 'org.wso2.carbon.apimgt:forum:6.5.272:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
    #        },
    # "n4": {'labels': ':AddedValue', 'id': 'org.wso2.carbon.apimgt:forum:6.5.279:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'},
    # "n5": {'labels': ':AddedValue', 'id': 'org.wso2.carbon.apimgt:forum:6.5.278:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'},
    # "n6": {'labels': ':AddedValue', 'value': '1', 'id': 'io.gravitee.common:gravitee-common:3.1.0:POPULARITY_1_YEAR', 'type': 'POPULARITY_1_YEAR'},
    # "n7": {'labels': ':AddedValue', 'value': '2', 'id': 'org.thepalaceproject.audiobook:org.librarysimplified.audiobook.parser.api:11.0.0:POPULARITY_1_YEAR', 'type': 'POPULARITY_1_YEAR'},
    # "n8": {'labels': ':AddedValue', 'value': '1', 'id': 'com.emergetools.snapshots:snapshots-shared:0.8.1:POPULARITY_1_YEAR', 'type': 'POPULARITY_1_YEAR'},
    # "n9": {'labels': ':AddedValue', 'id': 'se.fortnox.reactivewizard:reactivewizard-jaxrs:SPEED', 'type': 'SPEED', 'value': '0.08070175438596491'},
    # "n10":{'labels': ':AddedValue', 'id': 'cc.akkaha:asura-dubbo_2.12:SPEED', 'type': 'SPEED', 'value': '0.029411764705882353'},
    # "n11":{'labels': ':AddedValue', 'id': 'it.tidalwave.thesefoolishthings:it-tidalwave-thesefoolishthings-examples-dci-swing:SPEED', 'type': 'SPEED', 'value': '0.014814814814814815'},
    # "n12":{'labels': ':AddedValue', 'id': 'com.softwaremill.sttp.client:core_sjs0.6_2.13:2.0.2:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"7\\",\\"outdatedTimeInMs\\":\\"3795765000\\"}}'},
    # "n13":{'labels': ':AddedValue', 'id': 'com.ibeetl:act-sample:3.0.0-M6:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"2\\",\\"outdatedTimeInMs\\":\\"11941344000\\"}}'},
    # "n14":{'labels': ':AddedValue', 'id': 'com.softwaremill.sttp.client:core_sjs0.6_2.13:2.0.0:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"9\\",\\"outdatedTimeInMs\\":\\"4685281000\\"}}'},
    # "n15":{'labels': ':AddedValue', 'id': 'com.lihaoyi:ammonite_2.12.1:0.9.8:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"367\\",\\"outdatedTimeInMs\\":\\"142773884000\\"}}'},
    # "n0":{'labels': ':AddedValue', 'id': 'com.yahoo.vespa:container-disc:7.394.21:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"448\\",\\"outdatedTimeInMs\\":\\"105191360000\\"}}'},
    # }


    # # Example edges
    # edges = [
    #     ("n1", "n2", {"label": "relationship_AR"}),
    #     ("n1", "n12", {"label": "relationship_AR"}),
    #     ("n5", "n3", {"label": "relationship_AR"}),
    #     ("n1", "n6", {"label": "relationship_AR"}),
    #     ("n7", "n3", {"label": "relationship_AR"}),
    #     ("n1", "n11", {"label": "relationship_AR"}),
    #     ("n8", "n3", {"label": "relationship_AR"}),
    #     ("n4", "n7", {"label": "relationship_AR"}),
    #     ("n10", "n12", {"label": "relationship_AR"}),
    #     ("n5", "n13", {"label": "relationship_AR"}),
    #     ("n4", "n14", {"label": "relationship_AR"}),
    #     ("n13", "n0", {"label": "relationship_AR"}),
    #     ("n10", "n15", {"label": "relationship_AR"}),
    # ]
    

    caudiscover = CauDiscover(nodes, edges, sever_score_map)
    # prepare input from nodes and edges
    df = caudiscover._data_create()
    # extrat the features part out of node
    # ------ discover at scale process ---------
    pruned_G = caudiscover.das_dis_cve(df)
    
    ## compute causal chain
    shortest_paths, longest_chain = caudiscover.causal_chain_length(pruned_G)

    # ----------- feature analysis ------------ 

    # compute cve metrics
    feature_matrix = caudiscover.build_cve_metrics()

    # compute adjcency matrix
    adj_matrix = caudiscover.adj_matrix_build()

    num_features = 3
    params = np.ones(num_features)
    # compute causal score
    cal_score = caudiscover.causal_score(params, adj_matrix, feature_matrix)