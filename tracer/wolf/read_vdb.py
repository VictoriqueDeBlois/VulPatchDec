import json
import os

import pandas as pd
from bs4 import BeautifulSoup

from wolf.util import Base


def read_json(path):
    with open(path, 'r', encoding='utf-8') as fp:
        data = json.load(fp)
    return data


class VDBreader(Base):
    def __init__(self, logger=None, log_path=None):
        super().__init__(logger=logger, log_path=log_path)
        self.cve_list = None
        self.lang_list = None

    def _extract_json(self, path='./VDB.htm'):
        with open(path, 'r', encoding='utf-8') as fp:
            content = fp.read()
        soup = BeautifulSoup(content, 'html.parser')
        h = soup.find('h2')
        langs = soup.find_all('h2')

        results = {'repo_vul_list': []}

        for h in langs:
            lang = h.text[10:]
            repo_list = []
            for tr in h.find_next('tbody').find_all('tr')[:-1]:
                no, repo, cve, func = tr.text.strip().split('\n')

                repo: str
                n, v = repo.split()
                v = v[1:-1]
                repo = f'{v}##{n}'

                cve = cve.replace(',', '')
                cve = int(cve)

                func = func.replace(',', '')
                func = int(func)

                repo_list.append(
                    {"repo": repo,
                     "repo_cve_count": cve,
                     "repo_vul_count": func})

            results['repo_vul_list'].append({'lang': lang,
                                             'repo_list': repo_list})

        with open('vul_lang_list.json', 'w', encoding='utf-8') as fp:
            json.dump(results, fp, indent=4)

    def read_vdb(self, path='./vdb'):
        self.lang_list = read_json(os.path.join(self.base_path, path, 'vul_lang_list.json'))
        self.cve_list = read_json(os.path.join(self.base_path, path, 'vul_cve_list.json'))

    def find_repo(self, repo):
        for repo_list in self.cve_list['repo_cve_list']:
            if repo_list['repo'] == repo:
                return repo_list["repo_cve_list"]
        return None

    def get_cve_count(self, lang):
        for i in self.lang_list["repo_vul_list"]:
            if i['lang'] != lang:
                continue
            count = 0
            for j in i['repo_list']:
                count += int(j['repo_cve_count'])
            print(count)

    def create_df(self):
        data = {'lang': [],
                'owner': [],
                'repo': [],
                'cve': []}
        for i in self.lang_list["repo_vul_list"]:
            lang = i['lang']
            for j in i['repo_list']:
                repo = j['repo']
                cve_list = self.find_repo(repo)
                owner, repo = repo.split('##')
                if cve_list is None:
                    self._logger.error('can not find %s##%s', owner, repo)
                    continue
                for cve in cve_list:
                    data['lang'].append(lang)
                    data['owner'].append(owner)
                    data['repo'].append(repo)
                    data['cve'].append(cve)

        df = pd.DataFrame(data)
        return df


if __name__ == '__main__':
    r = VDBreader()
    r.read_vdb()
    d = r.create_df()
    d.to_csv('vdb.csv')
