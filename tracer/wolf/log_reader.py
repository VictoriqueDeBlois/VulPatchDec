import os
import re
from datetime import timedelta

import pandas
import pandas as pd

from wolf.read_vdb import VDBreader
from wolf.util import Base


class LoggerProcessor(Base):
    def __init__(self, logger=None, log_path=None):
        super().__init__(logger=logger, log_path=log_path)
        self.vdb = VDBreader(logger=logger, log_path=log_path)
        self.vdb.read_vdb()

    def get_commit_num(self):
        commit_path = './vdb_output/commit'
        commit_path = os.path.join(self.base_path, commit_path)
        commits = list(os.listdir(commit_path))
        return len(commits)

    def read_log(self):
        results = {}

        log_pattern = re.compile(r'([\d\-:, ]+) - (\w+?) - \[(\w+?)]: (.+)')
        cve_pattern = re.compile(r'CVE-\d+-\d+')
        finished_pattern = re.compile(r'CVE-\d+-\d+ finished, consuming time: ([\d:.]+)')

        log_path = './log/tracker.log'
        log_path = os.path.join(self.base_path, log_path)
        with open(log_path, 'r', encoding='utf-8') as fp:
            for line in fp:
                m = log_pattern.match(line)
                if m is None:
                    continue
                level = m.group(2)
                pipeline = m.group(3)
                msg = m.group(4)
                m = cve_pattern.search(msg)
                if m is None:
                    continue
                cve = m.group()
                if level == 'INFO':
                    finished = finished_pattern.match(msg)
                    if finished is None:
                        continue
                    time_str = finished.group(1)
                    time_obj = timedelta(hours=0, minutes=0, seconds=0)
                    time_obj += timedelta(hours=int(time_str.split(":")[0]), minutes=int(time_str.split(":")[1]),
                                          seconds=float(time_str.split(":")[2]))
                    seconds = time_obj.total_seconds()
                    results[cve] = ('finished', seconds)
                elif level == 'ERROR':
                    if cve in results and results[cve][0] == 'finished':
                        continue
                    results[cve] = ('error', pipeline)
        error = {'cve': [], 'error': []}
        finish = {'cve': [], 'time': []}
        for k, v in results.items():
            m, content = v
            if m == 'finished':
                finish['cve'].append(k)
                finish['time'].append(content)
            else:
                error['cve'].append(k)
                error['error'].append(content)
        f_df = pd.DataFrame.from_dict(finish)
        e_df = pd.DataFrame.from_dict(error)
        print('fin')
        print(f_df.describe())
        print('error')
        print(e_df['error'].value_counts())
        print(e_df.describe())

        return f_df, e_df

    def check_done(self, check_lang):
        results = {'lang': [], 'repo': [], 'done': [], 'all': []}
        for lang in self.vdb.lang_list["repo_vul_list"]:
            lang_str = lang["lang"]
            if lang_str not in check_lang:
                continue

            for repo in lang['repo_list']:
                repo_name = repo['repo']
                cve_list = self.vdb.find_repo(repo_name)
                if cve_list is None:
                    self._logger.error("cannot find %s", repo_name)
                    continue
                done = 0
                for cve in cve_list:
                    if os.path.exists(os.path.join(self.base_path, f'./vdb_output/commit/{cve}.txt')):
                        done += 1
                results['lang'].append(lang_str)
                results['repo'].append(repo_name)
                results['done'].append(done)
                results['all'].append(len(cve_list))
        df = pandas.DataFrame.from_dict(results)
        return df

    def check_done_detail(self, check_lang):
        results = {'cve': [], 'lang': [], 'repo': [], 'pipe': []}
        for lang in self.vdb.lang_list["repo_vul_list"]:
            lang_str = lang["lang"]
            if lang_str not in check_lang:
                continue

            for repo in lang['repo_list']:
                repo_name = repo['repo']
                cve_list = self.vdb.find_repo(repo_name)
                if cve_list is None:
                    self._logger.error("cannot find %s", repo_name)
                    continue
                for cve in cve_list:
                    pipe = -1
                    if os.path.exists(os.path.join(self.base_path, f'./vdb_output/commit/{cve}.txt')):
                        pipe = 4
                    for p in range(3, -1, -1):
                        if pipe == 4:
                            break
                        if os.path.exists(os.path.join(self.base_path, f'./pipeline/pipe{p}/{cve}.pkl')):
                            pipe = p
                            break

                    results['cve'].append(cve)
                    results['lang'].append(lang_str)
                    results['repo'].append(repo_name)
                    results['pipe'].append(pipe)
        df = pandas.DataFrame.from_dict(results)
        df.to_csv('detail.csv')
        describe = df.groupby(['lang', 'pipe']).count()['cve']
        langs = describe.keys().droplevel(1).unique()
        data = {
            '-1': [],
            '0': [],
            '1': [],
            '2': [],
            '3': [],
            '4': []
        }
        for lang in langs:
            d = describe[lang]
            for i in range(-1, 5):
                if i not in d:
                    data[str(i)].append(0)
                else:
                    data[str(i)].append(d[i])
        df = pd.DataFrame(data, index=list(langs))
        df['all'] = df.sum(axis=1)
        for lang in check_lang:
            self.vdb.get_cve_count(lang)
        return df


if __name__ == '__main__':
    log = LoggerProcessor()
    d = log.check_done_detail(['C', 'C++', 'Java', 'Javascript', 'Python', 'Go'])
    print(d)
