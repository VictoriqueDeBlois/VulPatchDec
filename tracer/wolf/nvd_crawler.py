import json
import os.path
import re

import pandas as pd

from wolf.commit_crawler import GitHubCommit
from wolf.util import Base
from wolf.util.crawler import GitHubCrawlerPool
from wolf.util.normal_crawler import BaseCrawlerPool


class NVDCrawler(Base):
    def __init__(self, logger=None, log_path=None):
        super().__init__(logger=logger, log_path=log_path)
        self.tmp_data = None
        self.tmp_data_year = None
        self.vdb = pd.read_csv(os.path.join(self.base_path, './vdb.csv'))
        self.github = GitHubCommit(logger=logger, log_path=log_path)
        os.makedirs(os.path.join(self.base_path, './vdb_output/commit_meta'), exist_ok=True)

    def load_tmp_data(self, path, year):
        if self.tmp_data_year == year:
            return
        json_path = os.path.join(self.base_path, path, f'nvdcve-1.1-{year}.json')
        with open(json_path, 'r', encoding='utf-8') as fp:
            self.tmp_data = json.load(fp)
            self.tmp_data_year = year

    def get_cve_meta_info_from_path(self, path, cve_id):
        json_path = os.path.join(self.base_path, path, f'{cve_id}.json')
        if os.path.exists(json_path) is False:
            self._logger.error("没有找到%s的json文件", cve_id)
            return None
        with open(json_path, 'r', encoding='utf-8') as fp:
            data = json.load(fp)
        cve_id = data['cve']['CVE_data_meta']['ID']

        cwes = data['cve']['problemtype']['problemtype_data']
        cwes = filter(lambda x: len(x['description']) != 0, cwes)
        cwes = list(map(lambda x: x['description'][0]['value'], cwes))

        cve_description = data['cve']['description']['description_data'][0]['value']

        cpes = []
        nodes = data['configurations']['nodes']
        nodes_string = json.dumps(nodes, indent=4)
        for line in nodes_string.split('\n'):
            line = line.strip()
            m = re.match(r"\"cpe23Uri\": \"(.+)\".*", line)
            if m:
                cpes.append(m.group(1))

        cvss2 = None
        cvss2_string = None
        if 'baseMetricV2' in data['impact']:
            cvss2 = data['impact']['baseMetricV2']['cvssV2']['baseScore']
            cvss2_string = data['impact']['baseMetricV2']['cvssV2']['vectorString']

        cvss3: None = None
        cvss3_string = None
        if 'baseMetricV3' in data['impact']:
            cvss3 = data['impact']['baseMetricV3']['cvssV3']['baseScore']
            cvss3_string = data['impact']['baseMetricV3']['cvssV3']['vectorString']

        meta = {
            'cve_id': cve_id,
            "cve_description": cve_description,
            "cwes": cwes,
            "cpes": cpes,
            "cvss2": cvss2,
            "cvss2_string": cvss2_string,
            "cvss3": cvss3,
            "cvss3_string": cvss3_string
        }
        return meta

    def get_commit(self, path, cve_id):
        os.makedirs(os.path.join(self.base_path, './github_diff'), exist_ok=True)

        url_path = os.path.join(self.base_path, path, f'{cve_id}.txt')
        urls = []
        with open(url_path, 'r', encoding='utf-8') as fp:
            for line in fp:
                line = line.strip()
                urls.append(line)

        infos = []
        for url in urls:
            if 'github' in url:
                info = self.github.get_commit(url)
                if info is None:
                    continue
                infos.append(info)
            elif 'kernel.org' in url:
                self._logger.warning('%s url: %s, cannot process', cve_id, url)
                # info = self.get_kernel_commit(url)
                # infos.append(info)
            elif 'apache.org' in url:
                self._logger.warning('%s url: %s, cannot process', cve_id, url)
                # info = self.get_apache_commit(url)
                # infos.append(info)
            else:
                self._logger.warning('%s url: %s, cannot process', cve_id, url)

        return infos

    def get_cve_all_info(self, cve_id):
        meta_json = os.path.join(self.base_path, './vdb_output/commit_meta', f'{cve_id}_meta.json')
        if os.path.exists(meta_json):
            return
        self._logger.info("%s 开始获取commit_meta", cve_id)
        cve_meta = self.get_cve_meta_info_from_path('./data/CVE/DataSet-NVD/NVDItems', cve_id)
        if cve_meta is None:
            return
        cve_commit_info = self.get_commit('./vdb_output/commit', cve_id)
        cve_meta['patches'] = cve_commit_info
        with open(meta_json, "w") as file:
            json.dump(cve_meta, file, indent=4)

    def get_kernel_commit(self, url):
        pass

    def get_apache_commit(self, url):
        pass


if __name__ == '__main__':
    pool = BaseCrawlerPool()
    pool.load_base_info(range(10))

    with open(os.path.join(pool.base_path, 'auth.txt'), 'r') as fp:
        auths = fp.readlines()
        res = []
        for a in auths:
            a = a.strip()
            if a.isspace():
                continue
            res.append(a)

    pool1 = GitHubCrawlerPool(logger='main')
    pool1.load_authorizations(res)

    c = NVDCrawler()
    # m = c.get_cve_meta_info_from_path('./data/CVE/DataSet-NVD/NVDItems', 'CVE-2020-3139')
    # print(m)
    c.get_cve_all_info('CVE-2013-3735')

    pool.stop()
    pool1.stop()
