import re
import gc
import os
import time
import re
import logging
import string
import warnings
import git
import string
import json
import pandas as pd
from tqdm import tqdm
from multiprocessing import Pool
import multiprocessing as mp
from nltk.corpus import stopwords
from collections import Counter
from util import *
warnings.filterwarnings("ignore")


def token(item, stopword_list):
    with open("../data/tokens/"+'tokens_useful.txt', 'r') as fp:
        useful_tokens = eval(fp.read())
    return [token for token in to_token(item, useful_tokens) if token not in stopword_list and len(token) > 1]


# =============== vuln_data ===============

def re_filepath(item):
    res = []
    find = re.findall(
        '(([a-zA-Z0-9]|-|_|/)+\.(cpp|cc|cxx|cp|CC|hpp|hh|C|c|h|py|php|java))',
        item)
    for item in find:
        res.append(item[0])
    return res


def re_file(item):
    res = []
    find = re.findall(
        '(([a-zA-Z0-9]|-|_)+\.(cpp|cc|cxx|cp|CC|hpp|hh|C|c|h|py|php|java))',
        item)
    for item in find:
        res.append(item[0])
    return res


def re_func(item):
    res = []
    find = re.findall("(([a-zA-Z0-9]+_)+[a-zA-Z0-9]+.{2})", item)
    for item in find:
        item = item[0]
        if item[-1] == ' ' or item[-2] == ' ':
            res.append(item[:-2])

    find = re.findall("(([a-zA-Z0-9]+_)*[a-zA-Z0-9]+\(\))", item)
    for item in find:
        item = item[0]
        res.append(item[:-2])

    find = re.findall("(([a-zA-Z0-9]+_)*[a-zA-Z0-9]+ function)", item)
    for item in find:
        item = item[0]
        res.append(item[:-9])
    return res


def get_tokens(text, List):
    return set([item for item in List if item in text])


with open("../data/vuln_type_impact.json", 'r') as f:
    vuln_type_impact = json.load(f)

vuln_type = set(vuln_type_impact.keys())
vuln_impact = set()
for value in vuln_type_impact.values():
    vuln_impact.update(value)

stopword_list = stopwords.words('english') + list(string.punctuation)


df = pd.read_csv("../data/vuln_data.csv")
df['functions'] = df['desc'].apply(re_func)
df['files'] = df['desc'].apply(re_file)
df['filepaths'] = df['desc'].apply(re_filepath)
df['vuln_type'] = df['desc'].apply(lambda item: get_tokens(item, vuln_type))
df['vuln_impact'] = df['desc'].apply(lambda item: get_tokens(item, vuln_impact))
df['desc_token'] = df['desc'].apply(lambda item: token(item, stopword_list))
df['desc_token_counter'] = df['desc_token'].apply(lambda item: Counter(item))


df = pd.read_csv("../data/vuln_data.csv")
vuln_df = df.merge(cwe[['cve', 'links']], how='left', on='cve')
vuln_df.to_csv("../data/vuln_data.csv", index=False)


# =============== code_data ===============
def get_code_info(repo, commit):
    outputs = repo.git.diff(commit + '~1',
                            commit,
                            ignore_blank_lines=True,
                            ignore_space_at_eol=True).split('\n')

    files, filepaths, funcs = [], [], []
    token_list = []
    for line in outputs:
        if line.startswith('diff --git'):
            line = line.lower()
            files.append(line.split(' ')[-1].strip().split('/')[-1])
            filepaths.append(line.split(" ")[-1].strip())
        elif line.startswith('@@ '):
            line = line.lower()
            funcs.append(line.split('@@')[-1].strip())
        elif (line.startswith('+') and not line.startswith('++')) or (
                line.startswith('-') and not line.startswith('--')):
            line = line.lower()
            token_list.extend(token(line[2:]))
    token_counter = Counter(token_list)
    return [commit, files, filepaths, funcs, token_counter]


def mid_func(item):
    return get_code_info(*item)


def multi_process_code(repo, commits, poolnum=5):
    length = len(commits)
    with Pool(poolnum) as p:
        ret = list(
            tqdm(p.imap(mid_func, zip([repo] * length, commits)),
                 total=length,
                 desc='get commits info'))
        p.close()
        p.join()
    return ret


df = pd.read_csv("../data/Dataset_5000.csv")
df = reduce_mem_usage(df)

total_df = []
repos = df.repo.unique()

gitpath = "../gitrepo/"
code_data_path = '../data/code_data'
if not os.path.exists(code_data_path):
    os.makedirs(code_data_path)

for reponame in repos:
    savepath = code_data_path+'/code_data_' + reponame + '.csv'
    if os.path.exists(savepath):
        continue

    print(reponame+"正在处理")

    repo = git.Repo(gitpath + reponame)
    commits = df[df.repo == reponame].commit.unique()
    code_data = multi_process_code(repo, commits)
    code_df = pd.DataFrame(
        code_data,
        columns=['commit', 'code_files', 'code_filepaths', 'code_funcs', 'code_token_counter'])
    code_df.to_csv(savepath, index=False)


# =============== mess_data ===============


def re_bug(item):
    find = re.findall('bug.{0,3}([0-9]{2, 5})', item)
    return set(find)


def re_cve(item):
    return set(re.findall('(cve-[0-9]{4}-[0-9]{1,7})', item))


df = pd.read_csv(dataset_path)
df = reduce_mem_usage(df)

with open("../data/vuln_type_impact.json", 'r') as f:
    vuln_type_impact = json.load(f)

vuln_type = set(vuln_type_impact.keys())
vuln_impact = set()
for value in vuln_type_impact.values():
    vuln_impact.update(value)

commit_mess_data = []
repos = df.repo.unique()
for reponame in repos:
    repo = git.Repo(gitpath + '/' + reponame)
    df_tmp = df[df.repo == reponame]
    for commit in tqdm(df_tmp.commit.unique()):
        mess = repo.commit(commit).message.lower()

        type_set = set()
        for value in vuln_type:
            if value in mess:
                type_set.add(value)

        impact_set = set()
        for value in vuln_impact:
            if value in mess:
                impact_set.add(value)

        bugs = re_bug(mess)
        cves = re_cve(mess)
        mess_token = token(mess, stopword_list)

        commit_mess_data.append([
            commit, bugs, cves, type_set, impact_set,
            Counter(mess_token)
        ])

commit_mess_data = pd.DataFrame(commit_mess_data,
                                columns=[
                                    'commit', 'mess_bugs', 'mess_cves',
                                    'mess_type', 'mess_impact',
                                    'mess_token_counter'
                                ])
commit_mess_data.to_csv("../data/mess_data.csv", index=False)


# =============== commit_data ===============

def get_info(repo, commit):
    outputs = repo.git.diff(commit + '~1',
                            commit,
                            ignore_blank_lines=True,
                            ignore_space_at_eol=True).split('\n')

    temp_commit = repo.commit(commit)
    # data to be collected
    weblinks, bug, issue, cve = [], [], [], []
    filepaths, funcs = [], []
    addcnt, delcnt = 0, 0
    # get commit message
    mess = temp_commit.message
    # get weblink bugID issueID cveID
    link_re = r'https?://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]'
    weblinks.extend(re.findall(link_re, mess))
    bug.extend(re.findall('[bB]ug[^0-9]{0,5}([0-9]{1,7})[^0-9]', mess))
    issue.extend(re.findall('[iI]ssue[^0-9]{0,5}([0-9]{1,7})[^0-9]', mess))
    cve.extend(re.findall('[CVEcve]{3}-[0-9]+-[0-9]+', mess))
    # get commit time
    datetime = pd.Timestamp(temp_commit.committed_date, unit='s')
    datetime = '{:04}{:02}{:02}'.format(datetime.year, datetime.month,
                                        datetime.day)

    for line in outputs:
        # get weblink bugID issueID cveID in code diff
        weblinks.extend(re.findall(link_re, line))
        bug.extend(re.findall('[bB]ug[^0-9]{0,5}([0-9]{1,7})[^0-9]', line))
        issue.extend(re.findall('[iI]ssue[^0-9]{0,5}([0-9]{1,7})[^0-9]', line))
        cve.extend(re.findall('[CVEcve]{3}-[0-9]+-[0-9]+', line))
        # get filepaths and funcnames in code diff
        # get added and deleted lines of code
        if line.startswith('diff --git'):
            filepath = line.split(' ')[-1].strip()[2:]
            filepaths.append(filepath)
        elif line.startswith('@@ '):
            funcname = line.split('@@')[-1].strip()
            funcname = funcs_preprocess(funcname)
            funcs.append(funcname)
        else:
            if line.startswith('+') and not line.startswith('++'):
                addcnt = addcnt + 1
            elif line.startswith(
                    '-') and not line.startswith('--'):
                delcnt = delcnt + 1

    return set(weblinks), set(bug), set(issue), set(cve), datetime, set(
        filepaths), set(funcs), addcnt, delcnt


def get_commit_info(data):
    out = get_info(data[0], data[1])
    return (data[1], out)


def multi_process_get_commit_info(repo, commits):
    length = len(commits)
    with Pool(5) as p:
        ret = list(
            tqdm(p.imap(get_commit_info, zip(*([repo] * length, commits))),
                 total=length,
                 desc='get commits info'))
        p.close()
        p.join()
    return ret


dataset_df = pd.read_csv('../data/Dataset_5000.csv')
repos = dataset_df.repo.unique()
dataset_df = reduce_mem_usage(dataset_df)
path = '../data/commit_info'
if not os.path.exists(path):
    os.makedirs(path)
for reponame in repos:
    repo = git.Repo('../gitrepo/{}'.format(reponame))
    commits = dataset_df[dataset_df.repo == reponame].commit.unique()
    result = multi_process_get_commit_info(repo, commits)
    savefile(dict(result), path + '/' + reponame + '_commit_info')
