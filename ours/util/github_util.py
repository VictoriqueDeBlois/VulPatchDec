import csv
import glob
import os
import pickle
import re
import shutil
import datetime
import csv
import config
import git
import git.util
from pydriller import Repository
from tqdm import tqdm

import config
from util.tool import longestCommonSubstr

tag_commands = ["git tag | sort -V > tag.txt", "git tag --sort=-committerdate > tag.txt"]


class CloneProgress(git.RemoteProgress):
    def __init__(self, name):
        super().__init__()
        self.pbar = tqdm(unit='B', unit_scale=True, unit_divisor=1024, desc=name)

    def update(self, op_code, cur_count, max_count=None, message=''):
        self.pbar.total = max_count
        self.pbar.n = cur_count
        self.pbar.refresh()


fail_repo = []

def get_commit_date(sha,cveid):
    if not os.path.exists(f'{config.TEST_PATH}{cveid}/repo_config.csv'):
        return False
    repo_file = open(f'{config.TEST_PATH}{cveid}/repo_config.csv', "r")
    reader = csv.reader(repo_file)
    first_row = next(reader)
    owner = first_row[0]
    repo = first_row[1]
    git_repo_path = f'{config.GIT_REPO_PATH}{owner}/{repo}'
    if os.path.exists(git_repo_path):
        pass
    else:
        return False
        # os.makedirs(f'./git/{owner}', exist_ok=True)
        # git.Repo.clone_from(f'https://github.com/{owner}/{repo}.git',
        #                     git_repo_path,
        #                     progress=CloneProgress(name=f'{owner}:{repo}'))
    date = None
    try:
        for commit in Repository(git_repo_path, single=sha).traverse_commits():
            date = commit.author_date
    except:
        return False
    return date

def extend_github_commit_node(path_to_repo, sha, CVE):
    with open(f'{config.TEST_PATH}{CVE}/repo_config.csv', 'r') as f:
        reader = csv.reader(f)
        first_row = next(reader)
        owner = first_row[0]
        repo = first_row[1]

    try:
        for commit in Repository(path_to_repo, single=sha).traverse_commits():
            date = commit.author_date
            message = commit.msg
    except:
        commit_content = get_title_by_commit_hash(sha, path_to_repo)
        if not commit_content:
            return
        date = commit_content['commit']['committer']['date']
        # 将日期字符串转化为 datetime 对象
        date = datetime.datetime.strptime(date, '%Y-%m-%dT%H:%M:%SZ')
        message = commit_content['commit']['message']

    # 计算30天前和30天后的日期
    date_day_3_pre = date - datetime.timedelta(days=30)  # 使用导入的 timedelta
    date_day_3_later = date + datetime.timedelta(days=30)

    # 遍历提交，查找符合条件的提交
    for commit in Repository(path_to_repo,
                             since=date_day_3_pre, to=date_day_3_later,
                             include_remotes=True).traverse_commits():
        candi_commit = f'https://github.com/{owner}/{repo}/commit/{commit.hash}'
        candi_message = commit.msg
        if candi_message == message or candi_message in message or message in candi_message or CVE in candi_message:
            if sha != commit.hash:
                with open(f'{config.RELATED_PATH}/{CVE}.csv', 'a+', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([candi_commit])
            with open(f'{config.RESULT_PATH}/{CVE}.csv', 'a+', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([candi_commit])


def get_repo_owner(cve):
    with open(f'{config.TEST_PATH}{cve}/repo_config.csv', 'r') as f:
        reader = csv.reader(f)
        first_row = next(reader)
        owner = first_row[0]
        repo = first_row[1]
    return  owner,repo


def get_title_by_commit_hash(hash, repo_path):
    # 根据 hash 值创建 commit 对象
    # 创建 Repo 对象
    try:
        repo = git.Repo(repo_path)
        commit = repo.commit(hash)
    except:
        return None
    return commit.summary



patterns = [r'-alpha.*', r'-beta.*', r'-rc.*', r'-ALPHA.*', r'-BETA.*', r'-RC.*', r'-pre.*', r'-PRE.*', r'-CR.*',
            r'-cr.*']

def remove_substrings_and_following(s):
    # 定义要删除的子串模式，考虑大小写

    for pattern in patterns:
        s = re.sub(pattern, '', s, flags=re.IGNORECASE)
    return s


import git
from datetime import datetime


def get_merge_time(repo_path, commit_hash):
    # 打开本地仓库
    repo = git.Repo(repo_path)

    # 获取主分支名称
    main_branch = repo.head.ref.tracking_branch().remote_head

    # 获取 commit 合并到主分支的时间
    merge_time = None
    for commit in repo.iter_commits(f'{main_branch}..{commit_hash}'):
        if commit.hexsha == commit_hash:
            merge_time = commit.committed_datetime
            break

    return merge_time

def contains_pattern(tag):
    for pattern in patterns:
        if re.search(pattern, tag):
            return True
    return False

#git_repo_path删除所有.csv结尾的文件
def remove_csv_files(git_repo_path):
    for file in glob.glob(git_repo_path+'/*.csv'):
            os.remove(file)
            print(f'{file} removed')

def get_all_commits_mes(dir,CVE):
    os.chdir(dir)
    print(CVE , dir)
    os.system("git log --pretty=format:'%H,%h,%s,%b' > all-commits.csv")
    os.mkdir(f'../pythonProject/CVEKnowledgeMap/all_commits/{CVE}')
    shutil.copy("all-commits.csv", f'../pythonProject/CVEKnowledgeMap/all_commits/{CVE}')
    os.chdir(config.PROJECT_ROOT)


def get_version_commits(dir, vera_version, CVE):
    tag_command = ""
    print(CVE)
    # os.system("git fetch --tags")
    if not contains_pattern(vera_version):
        vera_version = remove_substrings_and_following(vera_version)
        tag_command = "git tag -l | grep -viE 'alpha|beta|rc|cr|pre' | sort -V > tag.txt"

    else:
        tag_command = f'git tag -l | sort -V > tag.txt'
    if not os.path.exists(dir):
        print(f'{CVE} {dir} is empty')
        return
    os.chdir(dir)
    print(dir)
    if os.path.exists("tag.txt"):
        os.remove("tag.txt")
    os.system(tag_command)
    Last_Version = None
    Fixed_Version = None
    record = {}
    #如果tag.txt为空，将项目所有的commit写入{Last_Version}-{Fixed_Version}-commits.csv
    if os.path.getsize("tag.txt") == 0:
        os.system("git log --pretty=format:'%H,%h,%s,%b' > all-commits.csv")
        if not os.path.exists(config.TEST_PATH + CVE):
            os.makedirs(config.TEST_PATH + CVE)
        shutil.copy("all-commits.csv",config.TEST_PATH + CVE)
        os.chdir(config.PROJECT_ROOT)
        return Last_Version, Fixed_Version
    tags = []
    with open("tag.txt", "r") as f:

        Tags = f.read()
        Tags = Tags.split("\n")
        for r in Tags:
            l = r
            r = r.lower()
            if r == '':
                continue
            if not r.startswith('v') :
                r = 'v' + r
            record[r] = l
            tags.append(r)

    if not vera_version.__contains__('v'):
        vera_version = ('v' + vera_version).lower()
#tags排序
    tags.sort()
    if tags[0] == 'v':
        tags.remove('v')
    max_len = 0
    last_i = 0
    fix_i = 0
    for i, r in enumerate(tags):
        if i == 0:
            if r == vera_version :
                Fixed_Version = tags[i]
                #获取Fixed_Version的所有commit
                os.system(f"git log --pretty=format:'%H,%h,%s,%b' {Fixed_Version} > {Fixed_Version}-commits.csv")
                if not os.path.exists(config.TEST_PATH + CVE):
                    os.makedirs(config.TEST_PATH + CVE)
                shutil.copy(f'{Fixed_Version}-commits.csv',f'{config.TEST_PATH}/{CVE}')
                os.chdir(config.PROJECT_ROOT)
                return Last_Version, Fixed_Version
            continue
        if r == vera_version or 'v'+vera_version == r or vera_version in r or 'v'+r == vera_version:
            Last_Version = tags[i - 1]

            Fixed_Version = tags[i]
            last_i = i-1
            fix_i = i
            if Last_Version in Fixed_Version and contains_pattern(Last_Version):
                Last_Version = tags[i - 2]
                last_i = i - 2
            break
        #处理版本号不完全匹配的情况
        # if r>vera_version:
        #     Last_Version = tags[i - 1]
        #     Fixed_Version = tags[i]
        #     last_i = i-1
        #     fix_i = i
        #     #并且包含除数字和.以外的字符
        #     if Last_Version in Fixed_Version and contains_pattern(vera_version):
        #         Last_Version = tags[i - 2]
        #     break
        # 找最匹配的
        try:
            len = float(longestCommonSubstr(vera_version, r) / r.__len__())
        except:
            continue
        if len > max_len:
            max_len = len
            Last_Version = tags[i - 1]
            Fixed_Version = tags[i]
            last_i = i-1
            fix_i = i
    # 删除所有csv文件
    # for file in os.listdir():
    #     if file.endswith(".csv"):
    #         os.remove(file)
        if Fixed_Version is None:
            print(f'{CVE} {vera_version} not found')
            return None
    if Last_Version is None and Fixed_Version is not  None:
        #得到Fixed_Version 的对应提交
        if not os.path.exists(config.TEST_PATH + CVE):
            os.makedirs(config.TEST_PATH + CVE)
        os.system(f"git log --pretty=format:'%H,%h,%s,%b' {Fixed_Version} > {Fixed_Version}-commits.csv")
        shutil.copy(f'{Fixed_Version}-commits.csv', f'{config.TEST_PATH}/{CVE}')
    elif  Last_Version is not None and Fixed_Version is not  None:
        Last_Version = record[Last_Version]
        Fixed_Version = record[Fixed_Version]
        version_range = f'{Last_Version}..{Fixed_Version}'
        if '/' in Last_Version:
            Last_Version = Last_Version.replace('/', '-')
        if '/' in Fixed_Version:
            Fixed_Version = Fixed_Version.replace('/', '-')
        if os.path.exists(f'{Last_Version}-{Fixed_Version}-commits.csv'):
            os.remove(f'{Last_Version}-{Fixed_Version}-commits.csv')

        os.system(f"git log --pretty=format:'%H,%h,%s,%b' {version_range} > {Last_Version}-{Fixed_Version}-commits.csv")
        with open(f'{Last_Version}-{Fixed_Version}-commits.csv', 'r',encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            try:
                row_count = sum(1 for row in reader)
                if row_count< 10:
                    Last_Version = Tags[last_i - 2]
                    Fixed_Version = Tags[fix_i + 1]
                    print(f'{CVE} {version_range} commits is empty')
                    return Last_Version, Fixed_Version
            except:
                return None
        if not os.path.exists(config.TEST_PATH + CVE):
            os.makedirs(config.TEST_PATH + CVE)
        shutil.copy(f'{Last_Version}-{Fixed_Version}-commits.csv', f'{config.TEST_PATH}/{CVE}')

    #判断文件是否为空，为空则将所有提交保存
    if not os.path.exists(f'{Last_Version}-{Fixed_Version}-commits.csv') or os.path.getsize(f'{Last_Version}-{Fixed_Version}-commits.csv') == 0:
        os.system(f"git log --pretty=format:'%H,%h,%s,%b' > all-commits.csv")
        print(f'{CVE} all commits')
        if not os.path.exists(config.TEST_PATH + CVE):
            os.makedirs(config.TEST_PATH + CVE)
        shutil.copy(f'all-commits.csv',f'{config.TEST_PATH}/{CVE}')
    os.chdir(config.PROJECT_ROOT)
    return Last_Version, Fixed_Version



def extend_github_commit_node(path_to_repo, sha, CVE):
    with open(f'{config.TEST_PATH}{CVE}/repo_config.csv', 'r') as f:
        reader = csv.reader(f)
        first_row = next(reader)
        owner = first_row[0]
        repo = first_row[1]
    date = None
    message = None
    try:
        for commit in Repository(path_to_repo, single=sha).traverse_commits():
            date = commit.author_date
            message = commit.msg
    except:
        commit_content = get_title_by_commit_hash(sha, path_to_repo)
        if not commit_content:
            return
        date = commit_content['commit']['committer']['date']
        date = datetime.datetime.strptime(date, '%Y-%m-%dT%H:%M:%SZ')
        message = commit_content['commit']['message']

    date_day_3_pre = date - datetime.timedelta(days=30)
    date_day_3_later = date + datetime.timedelta(days=30)
    for commit in Repository(path_to_repo,
                             since=date_day_3_pre, to=date_day_3_later,
                             include_remotes=True).traverse_commits():
        candi_commit = f'https://github.com/{owner}/{repo}/commit/{commit.hash}'
        candi_message = commit.msg
        if candi_message == message or candi_message in message or message in candi_message or CVE in candi_message:
            if sha != commit.hash:
                with open(f'{config.RELATED_PATH}/{CVE}.csv', 'a+') as f:
                    writer = csv.writer(f)
                    writer.writerow([candi_commit])
                    f.close()
            with open(f'{config.RESULT_PATH}/{CVE}.csv', 'a+') as f:
                writer = csv.writer(f)
                writer.writerow([candi_commit])
                f.close()



def get_all_commits(owner, repo, path_to_repo, cve):
    if os.path.exists(f'{path_to_repo}'):
        get_all_commits_mes(f'{path_to_repo}', cve)
    else :
        print(f'{cve} {owner}:{repo} not found')
def get_fixed_version_commits(owner, repo, fixed_version, path_to_repo, cve):
    if os.path.exists(f'{path_to_repo}'):
        return get_version_commits(f'{path_to_repo}', fixed_version, cve)
    # else:
    #     return  None
    else:
        try:
            if path_to_repo.__contains__('tomcat') or path_to_repo.__contains__('symfony'):
                print('fail : zz'+cve)
                return None
            git.Repo.clone_from(f'https://{config.token}@github.com/{owner}/{repo}.git',
                                path_to_repo, progress=CloneProgress(name=f'{owner}:{repo}'))
        except:
            print(f'{cve} {owner}:{repo} clone failed')
            fail_repo.append((owner, repo))
            return
        return get_version_commits(f'{path_to_repo}', fixed_version, cve)


if __name__ == '__main__':
    # 指定本地仓库路径和要查询的 commit 的哈希值
    pipline = os.listdir(config.PIPILINE_PATH)
    for cve in pipline:
        if os.path.exists(f'{config.TEST_PATH}{cve}/repo_config.csv'):
            with open(f'{config.TEST_PATH}{cve}/repo_config.csv', 'r') as f:
                reader = csv.reader(f)
                first_row = next(reader)
                owner = first_row[0]
                repo = first_row[1]
                path_to_repo = f'{config.GIT_REPO_PATH}{owner}/{repo}'
        pkl_file = os.path.join(config.PIPILINE_PATH, cve, 'answer_prompt.pkl')

        if not os.path.exists(pkl_file):
            # print(f'{cve} not found')
            continue
        with open(pkl_file, 'rb') as file:
            answer_commits = pickle.load(file)
        for commit in answer_commits:
            extend_github_commit_node(path_to_repo, commit[0], cve)


