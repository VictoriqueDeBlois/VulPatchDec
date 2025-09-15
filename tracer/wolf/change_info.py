import concurrent.futures
import datetime
import json
import logging
import os
import queue
import re
import threading
import time
import zipfile

import requests
import wget
from bs4 import BeautifulSoup
from tqdm import tqdm


# 下载漏洞历史修改信息
class Bar:
    def __init__(self, name):
        self.last = 0
        self.bar = None
        self.name = name

    def bar_adaptive(self, current, total, width=80):
        if self.bar is None:
            self.bar = tqdm(unit='B', unit_scale=True, unit_divisor=1024, desc=self.name)
            self.bar.total = total
            self.bar.n = current
            self.last = current
            self.bar.display()
        else:
            self.bar.total = total
            self.bar.update(current - self.last)
            self.last = current


class Experiment:
    def __init__(self, year, max_workers=8):
        self.bar = None
        self.cve_year = str(year)
        self.max_workers = max_workers
        self._date = None
        self.proxies = {
            "http": "http://zcserver:7890",
            "https": "http://zcserver:7890"
        }
        # self.proxies = {}

        self._logger = None
        self._create_logger()

        self.stop_event = threading.Event()
        self.stop_event.set()

        self.http_error_queue = queue.SimpleQueue()

        os.makedirs(self.change_bak_path, exist_ok=True)
        os.makedirs(self.change_path, exist_ok=True)

    def _create_logger(self):
        self._logger = logging.getLogger('logger')
        logger_handler = logging.FileHandler(self.log_path, "a", encoding='utf-8')
        logger_handler.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - PID[%(process)d]: %(message)s")
        logger_handler.setFormatter(formatter)
        self._clean_logger()
        self._logger.addHandler(logger_handler)
        self._logger.setLevel(logging.INFO)

    def _clean_logger(self):
        for handler in self._logger.handlers[:]:
            if handler:
                handler.close()
                self._logger.removeHandler(handler)

    @property
    def base_path(self):
        if self._date is None:
            self._date = self.get_date()
        path = f'start_{self._date}'
        os.makedirs(path, exist_ok=True)
        return path

    @property
    def download_path(self):
        path = os.path.join(self.base_path, 'nvdcve_download')
        os.makedirs(path, exist_ok=True)
        return path

    @property
    def json_data_path(self):
        path = os.path.join(self.base_path, 'nvdcve')
        os.makedirs(path, exist_ok=True)
        return path

    @property
    def change_bak_path(self):
        path = os.path.join(self.base_path, f'change_bak_{self.cve_year}')
        os.makedirs(path, exist_ok=True)
        return path

    @property
    def change_path(self):
        path = os.path.join(self.base_path, f'change_{self.cve_year}')
        os.makedirs(path, exist_ok=True)
        return path

    @property
    def log_path(self):
        return os.path.join(self.base_path, f'change_info_{self.cve_year}.log')

    def get_nvd_download_info(self):
        download_info = {}
        url = 'https://nvd.nist.gov/vuln/data-feeds'
        with requests.get(url, proxies=self.proxies) as req:
            content = req.text
        soup = BeautifulSoup(content, 'html.parser')
        zips = soup.find_all('tr', attrs={'data-testid': re.compile(r'tableCveFeeds\d+-zip')})
        zips = map(lambda z: z.find('a')['href'], zips)
        for zip_url in zips:
            meta_url = zip_url.replace('json.zip', 'meta')
            name = meta_url[meta_url.rfind('/') + 1:-5]
            m = re.match(r'.+?-(\d{4})', name)
            if m:
                year = m.group(1)
                download_info[year] = {'name': name, 'meta': meta_url, 'zip': zip_url}
        return download_info

    def download_latest_nvd(self):
        info = self.get_nvd_download_info()
        os.makedirs(self.download_path, exist_ok=True)
        zip_url = info[self.cve_year]['zip']
        meta_url = info[self.cve_year]['meta']
        name = info[self.cve_year]['name']
        with requests.get(f'https://nvd.nist.gov{meta_url}', proxies=self.proxies) as req:
            content = req.text
        meta_file = os.path.join(self.download_path, f'{name}.meta')
        zip_file = os.path.join(self.download_path, f'{name}.json.zip')
        if os.path.exists(meta_file) and os.path.exists(zip_file):
            with open(meta_file, 'r', encoding='utf-8') as fp:
                exist_meta = fp.read()
            exist = ' '.join(exist_meta.splitlines())
            feed = ' '.join(content.splitlines())
            if exist == feed:
                return
        with open(meta_file, 'w', encoding='utf-8') as fp:
            fp.write(content)
        wget_bar = Bar(name)
        wget.download(f'https://nvd.nist.gov{zip_url}', out=self.download_path, bar=wget_bar.bar_adaptive)

    @staticmethod
    def get_ext_files(path, ext):
        collect = []
        for file in os.listdir(path):
            name, file_ext = os.path.splitext(file)
            if file_ext == ext:
                collect.append(os.path.join(path, file))
        return collect

    @staticmethod
    def get_date(format='%Y_%m_%d'):
        return datetime.datetime.now().strftime(format)

    def find_year_zip(self):
        info = {}
        zips = self.get_ext_files(self.download_path, '.zip')
        for zip_file in zips:
            m = re.match(r'.+?-(\d{4}).+', zip_file)
            if m:
                year = m.group(1)
                info[year] = zip_file
        return info

    def unzip_nvd(self):
        zips = self.find_year_zip()
        os.makedirs(self.json_data_path, exist_ok=True)
        if self.cve_year in zips:
            zip_file = zips[self.cve_year]
            with zipfile.ZipFile(zip_file, 'r') as zfp:
                zfp.extractall(self.json_data_path)
        else:
            self._logger.error(f'找不到cve {self.cve_year}的zip文件')

    def requests_get(self, url, retry=10):
        while retry > 0:
            try:
                self.stop_event.wait()
                with requests.get(url) as req:
                    req.raise_for_status()
                    content = req.text
                return content
            except requests.exceptions.RequestException as e:
                retry -= 1
                time.sleep(3)
                if retry <= 0:
                    m = re.search(r'CVE-\d+-\d+', url)
                    if m is None:
                        self._logger.error(f'未知错误url:{url}')
                        return None
                    cve_id = m.group()
                    if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403:
                        self._logger.error(f'{cve_id}网络访问403 | url:{url}')
                        if self.stop_event.is_set():
                            self.stop_event.clear()
                            print('访问遇到403，等待10分钟')
                            wait_timer = threading.Timer(10 * 60, lambda: self.stop_event.set())
                            wait_timer.start()
                    self._logger.error(f'{cve_id}网络访问出错:{e} | url:{url}')
                    self.http_error_queue.put(cve_id)
                    return None

    def bak_content(self, content, file):
        with open(os.path.join(self.change_bak_path, file), 'w', encoding='utf-8') as fp:
            fp.write(content)

    def load_and_save_content(self, url, file):
        bak_file_path = os.path.join(self.change_bak_path, file)
        if os.path.exists(bak_file_path):
            with open(bak_file_path, 'r', encoding='utf-8') as fp:
                content = fp.read()
        else:
            content = self.requests_get(url)
            if content is None:
                return None
            self.bak_content(content, file)
        return content

    def view_change(self, cve_id):
        content_json = {'cve_id': cve_id,
                        'change_history': []}

        base_url = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
        content = self.load_and_save_content(base_url, f'{cve_id}.html')
        if content is None:
            return False
        soup = BeautifulSoup(content, 'html.parser')
        change_history_div = soup.find('div', attrs={'id': 'vulnChangeHistoryDiv'})
        if change_history_div is None:
            self._logger.error(f'{cve_id}不能找到修改历史页面')
            return False
        change_count = change_history_div.find('small').text.strip().split(' ')[0]
        change_count = int(change_count)
        change_titles = change_history_div.find_all('span',
                                                    attrs={'data-testid': re.compile(r'vuln-change-history-\w+-\d+')})
        changes = change_history_div.find_all('td', attrs={'data-testid': re.compile(r'vuln-change-history-\d+-\w+')})

        for index in range(0, len(change_titles), 2):
            change_type = change_titles[index].text.strip()
            change_date = change_titles[index + 1].text.strip()
            content_json['change_history'].append({'change_type': change_type,
                                                   'change_date': change_date,
                                                   'changes': []})
        current_change_count = len(content_json['change_history'])
        if current_change_count != change_count:
            self._logger.warning(
                f'{cve_id}应该有{change_count}个修改历史，但是实际收集到{current_change_count}个历史记录')

        done = set()
        for index in range(0, len(changes), 4):
            attr = changes[index]['data-testid']
            history_index = attr.split('-')[-2]
            history_index = int(history_index)
            if history_index in done:
                continue
            history_action = changes[index].text.strip()
            history_type = changes[index + 1].text.strip()
            history_old = changes[index + 2]
            history_new = changes[index + 3]

            old_a = history_old.find('a')
            new_a = history_new.find('a')
            if old_a is not None or new_a is not None:
                if old_a is not None:
                    href = old_a['href']
                else:
                    href = new_a['href']
                url = f'https://nvd.nist.gov{href}'
                result = self.change_detail(content_json, url, history_index)
                if result:
                    done.add(history_index)
                    continue

            history_old = history_old.text.strip()
            history_new = history_new.text.strip()
            content_json['change_history'][history_index]['changes'] \
                .append({'history_action': history_action,
                         'history_type': history_type,
                         'history_old': history_old,
                         'history_new': history_new})

        with open(os.path.join(self.change_path, f'{cve_id}.json'), 'w', encoding='utf-8') as fp:
            json.dump(content_json, fp, indent=4)
        return True

    def change_detail(self, change_json, url, history_index):
        cve_id = change_json['cve_id']
        content = self.load_and_save_content(url, f'{cve_id}_{history_index}.html')
        if content is None:
            return False
        soup = BeautifulSoup(content, 'html.parser')
        changes = soup.find_all('td', attrs={'data-testid': re.compile(r'vuln-change-history-\d+-\w+')})
        if len(changes) == 0:
            change_type = change_json['change_history'][history_index]['change_type']
            change_date = change_json['change_history'][history_index]['change_date']
            self._logger.error(f'{cve_id} {change_type} {change_date} 不能获取具体信息')
            return False
        for index in range(0, len(changes), 4):
            history_action = changes[index].text.strip()
            history_type = changes[index + 1].text.strip()
            history_old = changes[index + 2].text.strip()
            history_new = changes[index + 3].text.strip()
            change_json['change_history'][history_index]['changes'] \
                .append({'history_action': history_action,
                         'history_type': history_type,
                         'history_old': history_old,
                         'history_new': history_new})
        return True

    def find_year_file(self):
        for file in os.listdir(self.json_data_path):
            if re.match(r'.+?-' + self.cve_year + r'\.json', file):
                return os.path.join(self.json_data_path, file)
        return None

    def run_year(self):
        file = self.find_year_file()
        if file is None:
            self._logger.error(f'找不到{self.cve_year}json文件')
            return
        with open(file, 'r', encoding='utf-8') as fp:
            d = json.load(fp)
        items = d['CVE_Items']
        cve_ids = map(lambda i: i['cve']['CVE_data_meta']['ID'], items)
        self.bar = tqdm(total=len(items), desc=self.cve_year)

        self._logger.info(f'cve {self.cve_year} 开始爬取数据')
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for cve_id in cve_ids:
                future = executor.submit(self.map_fn, cve_id)
                future.add_done_callback(self.future_done)

        self._logger.info(f'cve {self.cve_year} 对网络错误的cve爬取数据')
        cve_ids = []
        while not self.http_error_queue.empty():
            cve_id = self.http_error_queue.get()
            cve_ids.append(cve_id)
        self.bar = tqdm(total=len(cve_ids), desc='error cve')
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for cve_id in cve_ids:
                future = executor.submit(self.map_fn, cve_id)
                future.add_done_callback(self.future_done)

        self._logger.info(f'cve {self.cve_year} 数据检查')
        cve_ids = map(lambda i: i['cve']['CVE_data_meta']['ID'], items)
        for cve_id in cve_ids:
            if os.path.exists(os.path.join(self.change_path, f'{cve_id}.json')):
                continue
            self._logger.info(f'{cve_id} 缺失')
        self._logger.info(f'cve {self.cve_year} 爬取数据结束')

    def map_fn(self, cve_id):
        json_path = os.path.join(self.change_path, f'{cve_id}.json')
        if os.path.exists(json_path):
            if os.path.getsize(json_path) != 0:
                return True
        bak_html = os.path.join(self.change_bak_path, f'{cve_id}.html')
        if os.path.exists(bak_html):
            with open(bak_html, 'r', encoding='utf-8') as fp:
                content = fp.read()
            if re.search(r'<h1>403 Forbidden</h1>', content):
                os.remove(bak_html)
        return self.view_change(cve_id)

    def future_done(self, future):
        self.bar.update()


if __name__ == '__main__':
    for y in range(2022, 2009, -1):
        exp = Experiment(y)
        exp.download_latest_nvd()
        exp.unzip_nvd()
    # exp = Experiment(2021)
    # for file in tqdm(os.listdir('change_2021')):
    #     name, _ = os.path.splitext(file)
    #     exp.map_fn(name)
