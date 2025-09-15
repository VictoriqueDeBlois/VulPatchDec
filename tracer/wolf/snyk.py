import concurrent.futures
import json
import os
import re
from pathlib import Path
from urllib.parse import urljoin

import execjs
from bs4 import BeautifulSoup
from tqdm import tqdm

from wolf.util import Base
from wolf.util.normal_crawler import BaseCrawlerPool
from wolf.util.util import save_json, load_json


class SnykCrawler(Base):
    def __init__(self, logger=None, log_path=None):
        super().__init__(logger=logger, log_path=log_path)
        self.base_url = "https://security.snyk.io/vuln"
        self.search_page_path = os.path.join(self.base_path, './snyk/search_page')
        os.makedirs(self.search_page_path, exist_ok=True)
        self.vuln_page_path = os.path.join(self.base_path, './snyk/vuln_page')
        os.makedirs(self.vuln_page_path, exist_ok=True)
        self.raw_json_path = os.path.join(self.base_path, './snyk/raw_json')
        os.makedirs(self.vuln_page_path, exist_ok=True)
        self.result_path = os.path.join(self.base_path, './snyk/result')
        os.makedirs(self.result_path, exist_ok=True)

    @staticmethod
    def cache_download_page(url, path):
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as fp:
                page = fp.read()
        else:
            pool = BaseCrawlerPool()
            page = pool.get(url)
            if page is False:
                return None
            dirname = os.path.dirname(path)
            os.makedirs(dirname, exist_ok=True)
            with open(path, 'w', encoding='utf-8') as fp:
                fp.write(page)
        return page

    def search_cve(self, cve: str):
        cve = cve.upper()

        url = f'{self.base_url}?search={cve}'
        path = os.path.join(self.raw_json_path, f'{cve}.json')

        if os.path.exists(path):
            return

        search_vuln_data = []

        search_page = self.cache_download_page(url, os.path.join(self.search_page_path, cve, f'{cve}.html'))
        if search_page is None:
            return
        search_data = self.get_json_data_from_page(search_page)
        search_vuln_data.extend(search_data['data']['vulnData'])

        soup = BeautifulSoup(search_page, "html.parser")
        next_button = soup.find('a', attrs={'class': 'next'})
        while next_button is not None:
            href = next_button.get('href')
            url = urljoin(self.base_url, href)
            m = re.match(r'/vuln/(\d+).+?', href)
            if m is None:
                raise ValueError(f'{cve} url中找不到页数')
            number = m.group(1)
            search_page = self.cache_download_page(url, os.path.join(self.search_page_path, cve, f'{cve}_{number}.html'))
            if search_page is None:
                next_button = None
                continue
            search_data = self.get_json_data_from_page(search_page)
            search_vuln_data.extend(search_data['data']['vulnData'])
            soup = BeautifulSoup(search_page, "html.parser")
            next_button = soup.find('a', attrs={'class': 'next'})


        vuln_data = []
        for vuln in search_vuln_data:
            vuln_id = vuln['id']

            href = f'/vuln/{vuln_id}'
            url = urljoin(self.base_url, href)

            vul_page = self.cache_download_page(url, os.path.join(self.vuln_page_path, cve, f'{cve}-{vuln_id}.html'))
            if vul_page is None:
                continue

            data = self.get_json_data_from_page(vul_page)
            vuln_data.append(data)
        if len(vuln_data) > 0:
            save_json(vuln_data, path)
        else:
            save_json(None, path)
        return

    def get_json_data_from_page(self, content):
        soup = BeautifulSoup(content, "html.parser")
        data = soup.find('script', id='__NUXT_DATA__').text
        result = json.loads(data)
        result = self.parse_snyk_json(result)
        return result

    def get_valid_info(self, data):
        pass

    def run_cve(self, cve):

        try:
            self.search_cve(cve)
        except Exception as e:
            self._logger.error(f'{cve}: {e}')
        # info = self.get_valid_info(data)
        # save_json(info, result_path)

    def parse_snyk_json(self, source, ptr=0):
        target = source[ptr]
        if isinstance(target, list):
            parsed = [self.parse_snyk_json(source, i) for i in target if isinstance(i, int)]
            if len(target) > 0 and isinstance(target[0], str):
                return parsed[0] if len(parsed) == 1 else parsed
            return parsed
        elif isinstance(target, dict):
            return {k: self.parse_snyk_json(source, v) for k, v in target.items() if isinstance(v, int)}
        else:
            return target

    def run_crawler(self, cve_list):
        name = cve_list[0][4:8]
        progress_bar = tqdm(total=len(cve_list), desc=name)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for cve in cve_list:
                result_path = os.path.join(self.result_path, f'{cve}.json')
                if os.path.exists(result_path):
                    continue
                future = executor.submit(self.run_cve, cve)
                futures.append(future)

            for future in concurrent.futures.as_completed(futures):
                progress_bar.update(1)
