from neo4j import GraphDatabase

# Connect to Neo4j
uri = "bolt://localhost:7687"
username = "neo4j"
password = "Rencaijia08"
# database_name="metricsgraph"
database_name="neo4j"
driver = GraphDatabase.driver(uri, auth=(username, password))

def export_to_csv(tx):
    query = "CALL apoc.export.csv.all('graph_metric.csv', {delimiter: ','})"
    tx.run(query)

# def export_to_json(tx):
#     query = "CALL apoc.export.json.all('graph_metric.json', {})"
#     tx.run(query)

def export_to_graphml(tx):
    query = "CALL apoc.export.graphml.all('graph_no_metric.graphml', {})"
    tx.run(query)

with driver.session(database=database_name) as session:
    # session.write_transaction(export_to_csv)
    # session.write_transaction(export_to_json)
    session.write_transaction(export_to_graphml)