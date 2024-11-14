'''
 # @ Create Time: 2024-10-15 15:57:35
 # @ Modified time: 2024-10-31 14:18:30
 # @ Description: causal inference against the cve /cwe relationship in dependency graph
 
 
 '''

from semopy import Model
import pandas as pd
import dask.dataframe as dd
import logging


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


def cal_infe( cve_data):

    model_desc = """"
        neighbor_cve_score ~ node_cve_score
    
    """

    df = cve_data.compute() if isinstance(cve_data, dd.DataFrame) else cve_data

    # Create and fit SEM model
    model = Model(model_desc)
    model.fit(df)

    logger.info(f"the insights of fitted model is: {model.inspect()}")


if __name__ == "__main__":
    cal_infe(cve_data)
