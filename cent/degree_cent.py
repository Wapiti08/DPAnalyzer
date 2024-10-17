'''
 # @ Create Time: 2024-10-17 16:50:53
 # @ Modified time: 2024-10-17 16:50:59
 # @ Description: function to calculate degree based on nodes and edges
 '''

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
    
    return degree_cent