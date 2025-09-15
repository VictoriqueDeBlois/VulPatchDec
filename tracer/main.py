import logging
import os

import pandas as pd

from wolf.patch_tracer import Tracer
from wolf.util.crawler import GitHubCrawlerPool


def create_logger():
    log_path = './log'
    os.makedirs(log_path, exist_ok=True)
    main_log_path = os.path.join(log_path, 'main.log')

    logger = logging.getLogger('main')
    logger.setLevel(logging.INFO)
    logger_handler = logging.FileHandler(main_log_path, encoding='utf-8')
    logger_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - [%(threadName)s]: %(message)s")
    logger_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    warn_log_path = os.path.join(log_path, 'warn.log')
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

    logger = logging.getLogger('tracker')
    logger.setLevel(logging.INFO)
    logger_handler = logging.FileHandler(os.path.join(log_path, 'tracker.log'), encoding='utf-8')
    logger_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - [%(threadName)s]: %(message)s")
    logger_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    warn_log_path = os.path.join(log_path, 'tracker_warn.log')
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


if __name__ == '__main__':
    create_logger()

    with open('auth.txt', 'r') as fp:
        auths = fp.readlines()
        res = []
        for a in auths:
            a = a.strip()
            if a.isspace():
                continue
            res.append(a)

    pool = GitHubCrawlerPool(logger='main')
    pool.load_authorizations(res)

    t = Tracer(logger='tracker')
    # ['C', 'C++', 'Java', 'Javascript', 'Python', 'Go']
    df = pd.read_csv('detail.csv')
    df = df[df['lang'] == 'Java']
    # df = df[df['pipe'] == 0]

    cve_list = list(df['cve'])
    with open('java_cve_list.txt', 'w', encoding='utf-8') as fp:
        output = '\n'.join(cve_list)
        fp.write(output)
    # t.run_list(cve_list)

    # t.test(cve_list[3])

    pool.stop()
    print('done')
