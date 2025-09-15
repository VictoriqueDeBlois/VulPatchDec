import concurrent.futures
import json
import os

from tqdm import tqdm

from wolf.util import Base
from wolf.util.normal_crawler import BaseCrawlerPool
from wolf.util.util import load_json, save_json


class VeraCodeCrawler(Base):
    def __init__(self, logger=None, log_path=None):
        super().__init__(logger=logger, log_path=log_path)
        self.base_url = "https://api.sourceclear.com/catalog/search"
        self.search_path = os.path.join(self.base_path, './vera/search')
        os.makedirs(self.search_path, exist_ok=True)
        self.result_path = os.path.join(self.base_path, './vera/result')
        os.makedirs(self.result_path, exist_ok=True)
        self.component_path = os.path.join(self.base_path, './vera/component')
        os.makedirs(self.component_path, exist_ok=True)
        self.detail_path = os.path.join(self.base_path, './vera/detail')
        os.makedirs(self.detail_path, exist_ok=True)
        self.pool = BaseCrawlerPool()

    def get_valid_info_from_search(self, content, detail=False):
        content = content['model']
        if 'cve' not in content:
            return
        elif content['cve'] is None:
            return
        component_id = content['id']
        if detail:
            try:
                info = self.get_valid_info(content, raise_error=True)
            except KeyError:
                info = self.get_valid_info_from_api(component_id)
                if info is None:
                    info = self.get_valid_info(content, raise_error=False)
        else:
            info = self.get_valid_info(content, raise_error=False)
        return info

    def get_valid_info_from_api(self, component_id):
        url = f'https://api.sourceclear.com/artifacts/components/{component_id}'
        path = os.path.join(self.component_path, f'{component_id}.json')
        content = self.cache_download_json(url, path)
        if content is None:
            self._logger.error("cannot get component %s", component_id)
            return None
        return self.get_valid_info(content)

    @staticmethod
    def get_dict_item(dict_obj, key, raise_error):
        if key in dict_obj:
            return dict_obj[key]
        elif raise_error:
            raise KeyError()
        else:
            return None

    def get_valid_info(self, content, raise_error=False):
        component_id = self.get_dict_item(content, 'id', raise_error=raise_error)

        create_date = self.get_dict_item(content, 'createdDate', raise_error=raise_error)
        disclosure_date = self.get_dict_item(content, 'disclosureDate', raise_error=raise_error)
        released_date = self.get_dict_item(content, 'releasedDate', raise_error=raise_error)
        cve_published_date = self.get_dict_item(content, 'cvePublishedDate', raise_error=raise_error)

        cve = self.get_dict_item(content, 'cve', raise_error=raise_error)
        cwe = self.get_dict_item(content, 'cweId', raise_error=raise_error)
        language = self.get_dict_item(content, 'language', raise_error=raise_error)
        vulnerability_type = ', '.join(self.get_dict_item(content, 'vulnerabilityTypes', raise_error=raise_error))

        nvd_cvss_score = self.get_dict_item(content, 'nvdCvssScore', raise_error=raise_error)
        nvd_cvss_vector = self.get_dict_item(content, 'nvdCvssVector', raise_error=raise_error)
        nvd_cvss3_score = self.get_dict_item(content, 'nvdCvss3Score', raise_error=raise_error)
        nvd_cvss3_vector = self.get_dict_item(content, 'nvdCvss3Vector', raise_error=raise_error)
        srcclr_cvss3_score = self.get_dict_item(content, 'srcclrCvss3Score', raise_error=raise_error)
        srcclr_cvss3_vector = self.get_dict_item(content, 'srcclrCvss3Vector', raise_error=raise_error)

        components = []
        for component in self.get_dict_item(content, 'artifactComponents', raise_error=raise_error):
            coord_type = self.get_dict_item(component, 'componentCoordinateType', raise_error=raise_error)
            coord_one = self.get_dict_item(component, 'coordOne', raise_error=raise_error)
            coord_two = self.get_dict_item(component, 'coordTwo', raise_error=raise_error)

            names = [coord_type, coord_one, coord_two]
            names = filter(lambda x: x is not None, names)
            names = filter(lambda x: not (x.isspace() or len(x) == 0), names)
            names = map(lambda x: x.lower(), names)

            component_name = ':'.join(names)
            versions = []
            for ver in self.get_dict_item(component, 'versionRanges', raise_error=raise_error):
                version_range = self.get_dict_item(ver, 'versionRange', raise_error=raise_error)
                fix_version = self.get_dict_item(ver, 'updateToVersion', raise_error=raise_error)
                fix_date = self.get_dict_item(ver, 'fixDate', raise_error=raise_error)
                patch = self.get_dict_item(ver, 'patch', raise_error=raise_error)
                instances = list(map(lambda x: self.get_dict_item(x, 'componentInstanceHash', raise_error=raise_error),
                                     ver['componentInstances']))
                ver_info = {
                    'version_range': version_range,
                    'fix_version': fix_version,
                    'fix_date': fix_date,
                    'patch': patch,
                    'instances': instances
                }
                versions.append(ver_info)
            component_info = {
                'component_name': component_name,
                'versions': versions
            }
            components.append(component_info)

        valid_info = {
            "component_id": component_id,
            "create_date": create_date,
            "disclosure_date": disclosure_date,
            "released_date": released_date,
            "cve_published_date": cve_published_date,
            "cve": cve,
            "cwe": cwe,
            "language": language,
            "vulnerability_type": vulnerability_type,
            "nvd_cvss_score": nvd_cvss_score,
            "nvd_cvss_vector": nvd_cvss_vector,
            "nvd_cvss3_score": nvd_cvss3_score,
            "nvd_cvss3_vector": nvd_cvss3_vector,
            "srcclr_cvss3_score": srcclr_cvss3_score,
            "srcclr_cvss3_vector": srcclr_cvss3_vector,
            "components": components
        }
        return valid_info

    @staticmethod
    def cache_download_json(url, path):
        if os.path.exists(path):
            data = load_json(path)
        else:
            pool = BaseCrawlerPool()
            data = pool.get(url)
            if data is False:
                return None
            data = json.loads(data)
            save_json(data, path)
        return data

    def load_or_download_json(self, year, page):
        json_save_path = os.path.join(self.search_path, f'{year}_{page}.json')
        q = f'type:vulnerability released:{year - 1}-12-31..{year}-12-31'
        url = f'{self.base_url}?q={q}&page={page}'
        data = self.cache_download_json(url, json_save_path)
        if data is None:
            self._logger.error("cannot get %s-%s page", year, page)
        return data

    def run_crawler_per_year(self, year):
        data = self.load_or_download_json(year, 1)

        metadata = data['metadata']
        total_pages = metadata['totalPages']

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # 提交任务给线程池
            for page in range(1, total_pages + 1):
                executor.submit(self.run_year_per_page, year, page, False)

    def run_year_per_page(self, year, page, detail=False):
        data = self.load_or_download_json(year, page)
        if data is None:
            return
        for c in data['contents']:
            info = self.get_valid_info_from_search(c, detail)
            if info is None:
                continue
            cve = info['cve']
            result_path = os.path.join(self.result_path, f'CVE-{cve}.json')
            self._logger.info(f'{year}-{page}: CVE-{cve}.json')
            if os.path.exists(result_path):
                continue
            save_json(info, result_path)

    def crawl_all_detail_component(self):
        component_ids = []
        for file in tqdm(os.listdir(self.search_path), desc="搜索全部id"):
            search = load_json(os.path.join(self.search_path, file))
            component_ids += list(map(lambda content: content['model']['id'], search["contents"]))
        self._logger.info("完成id收集，一共%s个", len(component_ids))

        bar = tqdm(total=len(component_ids), desc='vera具体json')

        def update_bar(f):
            bar.update()

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            for i in component_ids:
                future = executor.submit(self.crawl_component, i)
                future.add_done_callback(update_bar)

    def crawl_component(self, component_id):
        component_path = os.path.join(self.component_path, f'{component_id}.json')
        if os.path.exists(component_path):
            data = load_json(component_path)
        else:
            url = f'https://api.sourceclear.com/artifacts/components/{component_id}'
            data = self.pool.get(url)
            if data is False:
                self._logger.error("vera id %s 爬取失败", component_id)
                return
            data = json.loads(data)
        cve = data["cve"]
        cve = f'CVE-{cve}'
        save_json(data, os.path.join(self.detail_path, f'{cve}.json'))


if __name__ == '__main__':
    base_pool = BaseCrawlerPool()
    base_pool.load_base_info(range(10))

    v = VeraCodeCrawler()
    for y in range(2016, 2024):
        v.run_crawler_per_year(y)

    base_pool.stop()
