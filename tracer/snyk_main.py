import logging
import os
from pathlib import Path

from wolf.snyk import SnykCrawler
from wolf.util.normal_crawler import BaseCrawlerPool


def create_logger():
    log_path = './log'
    os.makedirs(log_path, exist_ok=True)
    main_log_path = os.path.join(log_path, 'snyk_main.log')

    logger = logging.getLogger('main')
    logger.setLevel(logging.INFO)
    logger_handler = logging.FileHandler(main_log_path, encoding='utf-8')
    logger_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - [%(threadName)s]: %(message)s")
    logger_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    warn_log_path = os.path.join(log_path, 'snyk_warn.log')
    warn_logger_handler = logging.FileHandler(warn_log_path, encoding='utf-8')
    warn_logger_handler.setLevel(logging.WARNING)
    warn_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - [%(threadName)s --> (%(filename)s).%(funcName)s.%(lineno)s]: %(message)s")
    warn_logger_handler.setFormatter(warn_formatter)

    for h in logger.handlers:
        logger.removeHandler(h)
    logger.addHandler(logger_handler)
    # logger.addHandler(console_handler)
    logger.addHandler(warn_logger_handler)


if __name__ == '__main__':
    create_logger()

    base_pool = BaseCrawlerPool(logger='main')
    base_pool.load_base_info(range(10))

    s = SnykCrawler(logger='main')

    nvd_path = os.path.join(s.base_path, './data/CVE/DataSet-NVD/NVDItems')
    nvd_path = Path(nvd_path)

    for year in nvd_path.iterdir():
        cve_list = year.iterdir()
        cve_list = list(map(lambda x: x.stem, cve_list))
        s.run_crawler(cve_list)

    base_pool.stop()
