import os
from datetime import datetime

from wolf.util.normal_crawler import BaseCrawlerPool
from wolf.veracode import VeraCodeCrawler

if __name__ == '__main__':
    os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7890'
    os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7890'
    base_pool = BaseCrawlerPool()
    base_pool.load_base_info(range(10))

    v = VeraCodeCrawler()
    current_year = datetime.now().year
    for y in range(2016, current_year + 1):
        v.run_crawler_per_year(y)

    base_pool.stop()
