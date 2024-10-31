import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
from lxml import etree
from cent import between_cent, degree_cent, eigen_cent
import logging
from pathlib import Path

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
logger = logging.getLogger(__name__)
file_handler = logging.FileHandler('cent_cal.log')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)


def parse_graphml_in_chunks(file_path):
    context = etree.iterparse(file_path, events=("start", "end"))
    nodes = {}
    edges = []
    
    for event, elem in context:
        if event == "end" and elem.tag == "{http://graphml.graphdrawing.org/xmlns}node":
            # Process node
            node_id = elem.attrib['id']
            # Extract other attributes if needed, e.g. CVE_Severity
            attributes = {data.attrib['key']: data.text for data in elem.findall("{http://graphml.graphdrawing.org/xmlns}data")}
            nodes[node_id] = attributes
            elem.clear()  # Clear memory

        elif event == "end" and elem.tag == "{http://graphml.graphdrawing.org/xmlns}edge":
            # Process edge
            source = elem.attrib['source']
            target = elem.attrib['target']
            # Extract edge attributes
            attributes = {data.attrib['key']: data.text for data in elem.findall("{http://graphml.graphdrawing.org/xmlns}data")}
            edges.append((source, target, attributes))
            elem.clear()  # Clear memory
            
    return nodes, edges



if __name__ == "__main__":

    file_path = Path.cwd().parent.joinpath("data", "graph_metric.graphml").as_posix()
    # generate nodes and edges from graphml
    nodes, edges = parse_graphml_in_chunks(file_path)

    # ------ calculate the degree_centrality ------
    top_degree_cel = degree_cent.cal_degree_centrality(nodes, edges)
    logger.info(f"the top 10 nodes with highest degree centrality are: {top_degree_cel}")


    # ------ calculate the between_centrailty --------
    betcenter = between_cent.BetCent(nodes, edges)
    top_between_cel = betcenter.cal_between_cent()
    logger.info(f"the top 10 nodes with highest betweenness centrality are: {top_between_cel}")

    # ------ calculate the eigenvector centrality ------

    att_features = ["freshness", "popularity", "speed", "severity"]

    eigencenter = eigen_cent.EigenCent(nodes, edges, att_features)
    # process node attribute values to right format
    eigencenter._quan_attrs()
    eigencenter._covt_df()
    
    eigencenter._step_wise_reg(0.05, att_features)
    # analyse processed attributes
    eigencenter._weight_ana()

    # get the eigen centrality
    top_eigen_nodes = eigencenter.cal_weighted_eigen_cent(nodes)
    logger.info(f"the top 10 nodes with highest eigen centrality are: {top_eigen_nodes}")
