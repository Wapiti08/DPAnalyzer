'''
 # @ Create Time: 2024-10-17 16:50:53
 # @ Modified time: 2024-10-17 16:50:59
 # @ Description: function to calculate degree based on nodes and edges
 '''
import pickle
import networkx as nx
import json

def cal_degree_centrality(nodes, edges):
    '''
    :param nodes: dict type, {node: attrs}, attrs is dict type
    :param edges: list type, element is like (n_i, n_j, {'label':xx})
    '''
    # initialize the degree centrality dictionary
    degree_cent = {node: 0 for node in nodes.keys()}

    for edge in edges:
        source, target, _ = edge
        degree_cent[source] += 1
        degree_cent[target] += 1
    
    # Sort nodes by centrality and return the top 10
    top_10 = sorted(degree_cent.items(), key=lambda x: x[1], reverse=True)[:10]
    return top_10


def str_to_json(escaped_json_str):
    try:
        clean_str = escaped_json_str.replace('\\"', '"')
        return json.loads(clean_str)
    except ValueError as e:
        print(f"Error parsing JSON: {e}")
        return None

def get_addvalue_edges(edges):
    # source node is release, target node is addedvalue
    return {source: target for source, target, edge_att in edges if edge_att['label'] == "addedValues"}

def cve_check(target:str, nodes, addvalue_edges_dict):
    node = nodes[addvalue_edges_dict[target]]
    if 'type' in node and node['type'] == "CVE" and str_to_json(node["value"])['cve'] !=[]:
        return True
    else:
        return False


def cal_degree_software_with_cve(nodes, edges, addvalue_edges_dict):
    ''' check the software node with most connection of releases with cve
    (out-degree)
    '''
    # initialize the degree centrality dictionary
    degree_cent = {node: 0 for node in nodes.keys()}
    for edge in edges:
        # check with software nodes only
        source, target, attrs = edge
        if nodes[source]['labels'] == ':Artifact' and attrs['label'] == "relationship_AR":
            # check whether the target has non-blank cve
            if cve_check(target, nodes, addvalue_edges_dict):
                degree_cent[source] += 1
        else:
            continue

    # Sort nodes by centrality and return the top 10
    top_10 = sorted(degree_cent.items(), key=lambda x: x[1], reverse=True)[:10]
    return top_10


def cal_degree_release_with_cve(nodes, edges, addvalue_edges_dict):
    ''' check the release node (cve) with most connection of software
    (out-degree)
    
    '''
    # initialize the degree centrality dictionary
    degree_cent = {node: 0 for node in nodes.keys()}
    for edge in edges:
        # check with software nodes only
        source, target, attrs = edge
        if nodes[source]['labels'] == ':Release' and attrs['label'] == "dependency":
            # check whether the target has non-blank cve
            if cve_check(source, nodes, addvalue_edges_dict):
                degree_cent[source] += 1
        else:
            continue

    # Sort nodes by centrality and return the top 10
    top_10 = sorted(degree_cent.items(), key=lambda x: x[1], reverse=True)[:10]
    return top_10

def cal_degree_cent_releases(G):
    # Calculate degree centrality for the directed graph
    degree_centrality = nx.degree_centrality(G)
    
    # Sort the nodes based on degree centrality in descending order and get the top 10
    top_10_nodes = sorted(degree_centrality.items(), key=lambda item: item[1], reverse=True)[:10]

    return top_10_nodes

if __name__ == "__main__":

    nodes = {
    "n1":  {'labels': ':Artifact', 
            'id': 'org.wso2.carbon.apimgt:forum:6.5.275:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
            },
    "n2": {'labels': ':Artifact', 
           'id': 'org.wso2.carbon.apimgt:forum:6.5.276:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
           },
    "n3": {'labels': ':Artifact', 'id': 'org.wso2.carbon.apimgt:forum:6.5.272:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'
           },
    "n4": {'labels': ':Artifact', 'id': 'org.wso2.carbon.apimgt:forum:6.5.279:CVE', 'type': 'CVE', 'value': '{\\"cve\\":[{\\"cwe\\":\\"[CWE-20]\\",\\"severity\\":\\"MODERATE\\",\\"name\\":\\"CVE-2023-6835\\"}]}'},
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
    "n0":{'labels': ':AddedValue', 'id': 'com.yahoo.vespa:container-disc:7.394.21:FRESHNESS', 'type': 'FRESHNESS', 'value': '{\\"freshness\\":{\\"numberMissedRelease\\":\\"448\\",\\"outdatedTimeInMs\\":\\"105191360000\\"}}'},
    'n16': {'labels': ':Release', 'id': 'org.wso2.carbon.identity.framework:org.wso2.carbon.identity.cors.mgt.core:5.20.111', 'version': '5.20.111', 'timestamp': '1626148242000'},
    'n17': {'labels': ':Release', 'id': 'org.apache.camel.quarkus:camel-quarkus-kotlin-parent:1.0.0-M4', 'version': '1.0.0-M4', 'timestamp': '1583239943000'},
    'n18': {'labels': ':Release', 'id': 'org.apache.camel.quarkus:camel-quarkus-kotlin-parent:1.0.0-M3', 'version': '1.0.0-M3', 'timestamp': '1579861029000'},
    'n19': {'labels': ':Release', 'id': 'org.wso2.carbon.identity.framework:org.wso2.carbon.identity.cors.mgt.core:5.20.113', 'version': '5.20.113', 'timestamp': '1626179580000'},
    'n20': {'labels': ':Release', 'id': 'org.wso2.carbon.identity.framework:org.wso2.carbon.identity.cors.mgt.core:5.20.112', 'version': '5.20.112', 'timestamp': '1626170945000'},
    'n21': {'labels': ':Release', 'id': 'org.wso2.carbon.identity.framework:org.wso2.carbon.identity.cors.mgt.core:5.20.115', 'version': '5.20.115', 'timestamp': '1626340086000'},
    'n22': {'labels': ':Release', 'id': 'org.apache.camel.quarkus:camel-quarkus-kotlin-parent:1.0.0-M2', 'version': '1.0.0-M2', 'timestamp': '1576600059000'},
    'n23': {'labels': ':Release', 'id': 'org.apache.camel.quarkus:camel-quarkus-kotlin-parent:1.0.0-M6', 'version': '1.0.0-M6', 'timestamp': '1586476381000'},
    'n24': {'labels': ':Release', 'id': 'org.wso2.carbon.identity.framework:org.wso2.carbon.identity.cors.mgt.core:5.20.114', 'version': '5.20.114', 'timestamp': '1626266264000'},
    'n25': {'labels': ':Release', 'version': '0.5.0', 'timestamp': '1669329622000', 'id': 'com.splendo.kaluga:alerts-androidlib:0.5.0'},

    }


    # Example edges
    edges = [
        ("n1", "n2", {"label": "relationship_AR"}),
        ("n1", "n12", {"label": "relationship_AR"}),
        ("n5", "n3", {"label": "relationship_AR"}),
        ("n1", "n4", {"label": "relationship_AR"}),
        ("n7", "n3", {"label": "relationship_AR"}),
        ("n1", "n11", {"label": "relationship_AR"}),
        ("n8", "n3", {"label": "relationship_AR"}),
        ("n4", "n7", {"label": "dependency"}),
        ("n10", "n12", {"label": "relationship_AR"}),
        ("n5", "n13", {"label": "relationship_AR"}),
        ("n4", "n14", {"label": "relationship_AR"}),
        ("n13", "n0", {"label": "dependency"}),
        ("n10", "n15", {"label": "relationship_AR"}),
        ("n1", "n16", {"label": "dependency"}),
        ("n19", "n25", {"label": "relationship_AR"}),
        ("n5", "n21", {"label": "relationship_AR"}),
        ("n21", "n23", {"label": "relationship_AR"}),
        ("n19", "n24", {"label": "relationship_AR"}),
        ("n4", "n19", {"label": "relationship_AR"}),
    ]

    print(cal_degree_software_with_cve(nodes, edges))
    print(cal_degree_release_with_cve(nodes, edges))