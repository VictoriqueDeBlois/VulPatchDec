import logging
import os

import pandas as pd
import tqdm

from wolf.nvd_crawler import NVDCrawler
from wolf.util.crawler import GitHubCrawlerPool
from wolf.util.normal_crawler import BaseCrawlerPool
from wolf.util.util import get_datetime


def create_logger(log_file_name):
    date_string = get_datetime()
    log_path = './log'
    os.makedirs(log_path, exist_ok=True)
    main_log_path = os.path.join(log_path, f'{log_file_name}_{date_string}.log')

    logger = logging.getLogger('main')
    logger.setLevel(logging.INFO)
    logger_handler = logging.FileHandler(main_log_path, encoding='utf-8')
    logger_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - [%(threadName)s]: %(message)s")
    logger_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    warn_log_path = os.path.join(log_path, f'{log_file_name}_warn_{date_string}.log')
    warn_logger_handler = logging.FileHandler(warn_log_path, encoding='utf-8')
    warn_logger_handler.setLevel(logging.WARNING)
    warn_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - [%(threadName)s --> (%(filename)s).%(funcName)s.%(lineno)s]: %(message)s")
    warn_logger_handler.setFormatter(warn_formatter)

    for h in logger.handlers:
        logger.removeHandler(h)
    logger.addHandler(logger_handler)
    logger.addHandler(console_handler)
    logger.addHandler(warn_logger_handler)

    logger = logging.getLogger('network')
    logger.setLevel(logging.INFO)
    logger_handler = logging.FileHandler(os.path.join(log_path, f'{log_file_name}_net_{date_string}.log'),
                                         encoding='utf-8')
    logger_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - [%(threadName)s]: %(message)s")
    logger_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    for h in logger.handlers:
        logger.removeHandler(h)
    logger.addHandler(logger_handler)
    logger.addHandler(console_handler)


if __name__ == '__main__':
    create_logger('js_commit_meta')

    with open('auth.txt', 'r') as fp:
        auths = fp.readlines()
        res = []
        for a in auths:
            a = a.strip()
            if a.isspace():
                continue
            res.append(a)

    pool = GitHubCrawlerPool(logger='network')
    pool.load_authorizations(res)

    base_pool = BaseCrawlerPool(logger='network')
    base_pool.load_base_info(range(10))

    nvd = NVDCrawler(logger='main')

    # ['C', 'C++', 'Java', 'Javascript', 'Python', 'Go']
    df = pd.read_csv('detail.csv')
    df = df[df['lang'] == 'Javascript']
    df = df[df['pipe'] == 4]
    #
    cve_list = list(df['cve'])

    for cve in tqdm.tqdm(cve_list):
        nvd.get_cve_all_info(cve)

    pool.stop()
    base_pool.stop()
    print('done')
