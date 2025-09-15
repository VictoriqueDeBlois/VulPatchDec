import csv
import glob
import json
import os
import re

import git.util
from tqdm import tqdm

import config
from util.github_util import get_fixed_version_commits, remove_csv_files, get_all_commits
from  util.vera_util import get_vera_found

main_path = '/data/zy/pythonProject/CVEKnowledgeMap'

import git

git.Git.GIT_PYTHON_GIT_EXECUTABLE = '/home/xuhaoran/.conda/envs/torch/bin/git'

class CloneProgress(git.RemoteProgress):
    def __init__(self, name):
        super().__init__()
        self.pbar = tqdm(unit='B', unit_scale=True, unit_divisor=1024, desc=name)

    def update(self, op_code, cur_count, max_count=None, message=''):
        self.pbar.total = max_count
        self.pbar.n = cur_count
        self.pbar.refresh()


# for commit in Repository(f'{path_to_repo}',
#                          from_tag=last_version,to_tag=fixed_verision).traverse_commits():
#     print(commit.hash, commit.author.name, commit.author_date, commit.msg)


#
# def get_commit_messages_v2(keys1):
#     for cve in keys1:
#         version_commits = {}
#
#         with open(f'/data/zy/pythonProject/CVEKnowledgeMap/resource/vera.csv', "r") as f:
#             reader = csv.reader(f)
#             for row in reader:
#                 if cve == row[0]:
#                     fixed_version = row[1]
#                     commit = row[2]
#                     if fixed_version in version_commits:
#                         version_commits[fixed_version].add(commit)
#                     else:
#                         version_commits[fixed_version] = set()
#                         version_commits[fixed_version].add(commit)
#                     break
#         if version_commits is None or version_commits.__len__() == 0:
#             print(f'{cve} version_commits is None')
#             continue
#         index =0
#         for fixed_version in version_commits:
#             commits = version_commits[fixed_version]
#             commit = commits.pop()
#             commits.add(commit)
#             m = re.match(r'https*://github.com/(.+?)/(.+?)/commit/(.+?)', commit)
#
#
#             if m is None:
#                 print(cve+"  m is None : " + commit)
#                 continue
#             owner = m.group(1).lower()
#             repo = m.group(2).lower()
#             # if os.path.exists(f'{config.OUTPUT_PATH}{cve}'):
#             #     repo_config = open(f'{config.OUTPUT_PATH}{cve}/repo_config.csv', "w")
#             #     writer = csv.writer(repo_config)
#             #     writer.writerow([owner, repo])
#             #     continue
#             # # todo :先找Vul下的git目录
#             # else:
#             os.makedirs(f'{config.OUTPUT_PATH}{cve}', exist_ok=True)
#             if index ==0:
#                 remove_csv_files(f'{config.GIT_REPO_PATH}{owner}/{repo}')
#                 index=1
#             if  os.path.exists(f'{config.PRODU_VER}{cve}.csv'):
#                 with open (f'{config.PRODU_VER}{cve}.csv', "r") as f:
#                     reader = csv.reader(f)
#                     for row in reader:
#                         product = row[0]
#                         version = row[1]
#                         fixed_version = version
#             if get_fixed_version_commits(owner, repo, fixed_version, f'{config.GIT_REPO_PATH}{owner}/{repo}',
#                                       cve) is None:
#                 print(f'{cve} {fixed_version} {commit} is wrong')
#             #todo 用的pro_
#             repo_config = open(f'{config.OUTPUT_PATH}{cve}/repo_config.csv', "w")
#             writer = csv.writer(repo_config)
#             writer.writerow([owner, repo])

def get_commit_messages(keys1):
    for cve in keys1:
        print(cve)
        version_commits = get_vera_found(f'{config.VERA_PATH}{cve}.json')
        if version_commits is None or version_commits.__len__() == 0:
            print(f'{cve} version_commits is None')
            continue
        index =0
        for fixed_version in version_commits:
            commits = version_commits[fixed_version]
            commit = commits.pop()
            commits.add(commit)
            m = re.match(r'https*://github.com/(.+?)/(.+?)/commit/(.+?)', commit)


            if m is None:
                print(cve+"  m is None : " + commit)
                continue
            owner = m.group(1).lower()
            repo = m.group(2).lower()
            # if os.path.exists(f'{config.OUTPUT_PATH}{cve}'):
            #     repo_config = open(f'{config.OUTPUT_PATH}{cve}/repo_config.csv', "w")
            #     writer = csv.writer(repo_config)
            #     writer.writerow([owner, repo])
            #     continue
            # # todo :先找Vul下的git目录
            # else:
            os.makedirs(f'{config.OUTPUT_PATH}{cve}', exist_ok=True)
            if index ==0:
                remove_csv_files(f'{config.GIT_REPO_PATH}{owner}/{repo}')
                index=1
            if  os.path.exists(f'{config.PRODU_VER}{cve}.csv'):
                with open (f'{config.PRODU_VER}{cve}.csv', "r") as f:
                    reader = csv.reader(f)
                    for row in reader:
                        product = row[0]
                        version = row[1]
                        fixed_version = version
            if get_fixed_version_commits(owner, repo, fixed_version, f'{config.GIT_REPO_PATH}{owner}/{repo}',
                                      cve) is None:
                print(f'{cve} {fixed_version} {commit} is wrong')
            #todo 用的pro_
            if not os.path.exists(f'{config.TEST_PATH}/{cve}'):
                os.mkdir(f'{config.TEST_PATH}{cve}')
            repo_config = open(f'{config.TEST_PATH}{cve}/repo_config.csv', "w")
            writer = csv.writer(repo_config)
            writer.writerow([owner, repo])
def get_all_commits_message(cves):
    for folder in cves:
        if not os.path.exists(f'{config.TEST_PATH}{folder}/repo_config.csv'):
            print(f'{folder} repo_config.csv is None')
            return None
        repo_file = open(f'{config.TEST_PATH}{folder}/repo_config.csv', "r")
        reader = csv.reader(repo_file)
        try:
            first_row = next(reader)  # 读取第一行
        except StopIteration:
            print(f'{folder} same_patch 是空的，跳过处理')
            return  # 如果文件为空，返回或跳过处理
        owner = first_row[0]
        repo = first_row[1]
        get_all_commits(owner, repo, f'{config.GIT_REPO_PATH}{owner}/{repo}',
                                  folder)
        repo_config = open(f'/data/zy/pythonProject/CVEKnowledgeMap/all_commits/{folder}/repo_config.csv', "w")
        writer = csv.writer(repo_config)
        writer.writerow([owner, repo])

if __name__ == '__main__':
    # get_fixed_version_commits('symfony', 'symfony', 'jackson-databind-2.1.5..2.10.0', './git_repo/symfony/symfony')
    data1 = set()


    #todo 正常测试深度数据集
    # with open('../resource/depth_dataset.csv', "r") as f:
    #     reader = csv.reader(f)
    #     for row in reader:
    #         data1.add(row[0])
    # # 获取字典键并存储在一个列表中
    # with open('../test_cve_not_include_benchline_commit.txt',"r") as f:
    #     data1 = f.readlines()
    #     data1 = [x.strip() for x in data1]
    # keys1 = list(data1)
    # #删除OUTPUT、TEST下的keys中的目录

    # keys1 = ["CVE-2016-10567"]
    # tag为空
    # with open('../test_cve_not_include_commit.txt', "r") as f:
    #     data1 = f.readlines()
    #     data1 = [x.strip() for x in data1]
    # keys2 = list(data1)
    # # keys = keys1+keys2
    # # output = os.listdir(config.OUTPUT_PATH)
    # # cves = []
    # # for cve in keys1:
    # #     if cve not in output and 'CVE' in cve:
    # #         cves.append(cve)
    with open(f'/data/zy/pythonProject/CVEKnowledgeMap/resource/dataset1.txt', "r") as f:
        cves = f.readlines()
        cves = [x.strip() for x in cves]
    tests = os.listdir(config.TEST_PATH)
    data1 = set(cves) - set(tests)
    get_commit_messages(data1)
    # print(util.github_util.fail_repo)
    # pickle.dump(util.github_util.fail_repo, open(f'./cve/fail_repo.pkl', "wb"))

    # with open('resource/vera.csv', 'r') as f:
    #     reader = csv.reader(f)
    #     for row in reader:
    #         cves.append(row[0])


    # cves = set(os.listdir(config.TEST_PATH2)) - set(os.listdir(config.TEST_PATH))
    # cves = list(set(cves))
    # cves = ['CVE-2024-34899']
    # get_commit_messages_v2(set(cves))

    # cves = os.listdir(config.TEST_PATH)
    # get_all_commits_message(cves)