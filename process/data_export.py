from neo4j import GraphDatabase
from dotenv import load_dotenv
import os

# load environment
load_dotenv()

# load password
PASSWORD = os.getenv("PASSWORD")

# Connect to Neo4j
uri = "bolt://localhost:7687"
username = "neo4j"
password = PASSWORD
# database_name="metricsgraph"
database_name="neo4j"
driver = GraphDatabase.driver(uri, auth=(username, password))

def export_to_csv(tx):
    query = "CALL apoc.export.csv.all('graph_metric.csv', {delimiter: ','})"
    tx.run(query)

def export_to_graphml(tx):
    query = "CALL apoc.export.graphml.all('graph_no_metric.graphml', {})"
    tx.run(query)

with driver.session(database=database_name) as session:
    # session.write_transaction(export_to_csv)
    # session.write_transaction(export_to_json)
    session.write_transaction(export_to_graphml)