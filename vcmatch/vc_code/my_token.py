import os
import time
import pandas as pd
from tqdm import tqdm
from multiprocessing import Pool
import multiprocessing as mp
from util import *

gitpath = "../gitrepo/"
tokenpath = "../data/tokens/"
gitlogpath = "../data/gitlog/"
gitcommit_path = '../data/gitcommit/'
gitrepo_path = '../gitrepo/'


def prepare_token_path():
    if not os.path.exists(gitlogpath):
        os.makedirs(gitlogpath)
    if not os.path.exists(tokenpath):
        os.makedirs(tokenpath)


# tokenize the text
def multi_process_line(lines, pool_num = 5):
    with Pool(pool_num) as p:
        res = list(
            tqdm(p.imap(to_token, lines), total=len(lines),
                 desc='process'))
        p.close()
        p.join()
    ret = set()
    for item in res:
        ret.update(item)
    return ret


# get commit tokens
def get_commit_tokens(reponame, token_path, gitlogpath, pool_num = 5):
    t1 = time.time()
    tokens = set()
    with open(gitlogpath+'Log_{}.txt'.format(reponame), 'r',errors='ignore') as fp:
        stop = False
        #  avoid its too large
        while not stop:
            lines = []
            for i in range(5000000):
                line = fp.readline()
                if line == '':
                    stop = True
                    break
                lines.append(line)
            token = multi_process_line(lines, pool_num)
            tokens.update(token)
    t2 = time.time()
    # save tokens to file
    with open(token_path+'tokens_{}.txt'.format(reponame), 'w+') as fp:
        fp.write(str(tokens))


def get_tokens(path):
    with open(path, 'r',  errors='ignore') as fp:
        lines = fp.readlines()
    return set(multi_process_line(lines))



prepare_token_path()
### get commit-related token
df = pd.read_csv("../data/data.csv")
repos = df.repo.nunique()
for reponame in repos:
    t1 = time.time()
    # print('{} repo starts to process...'.format(reponame))
    
    logpath = gitlogpath+"Log_{}.txt".format(reponame)
    if not os.path.exists(logpath):
        # change to git repo folder
        os.chdir(gitpath + reponame)
        # save git log to file
        os.system('git log -p --color=never > '+logpath)
        get_commit_tokens(reponame, tokenpath, gitlogpath)
        os.remove(logpath)
    t2 = time.time()
    # print('{} repo is completed...'.format(reponame))
    # print("total cost {}s".format(int(t2-t1)))

paths = [tokenpath+'tokens_{}.txt'.format(reponame) for reponame in repos]
commit_tokens = set()
for path in tqdm(paths):
    with open(path, 'r') as fp:
        token = eval(fp.read())
        commit_tokens.update(token)
    # remove unuse file
    os.remove(path)
with open(tokenpath+'tokens_commit.txt', 'w')  as fp:
    fp.write(str(commit_tokens))

### get vulnerability-related token
vuln_token = set()
vuln_token.update(get_tokens("../data/vuln_data.csv"))
with open(tokenpath+'/tokens_vulu.txt', 'w+') as fp:
    fp.write(str(vulu_token))

### get useful token
total_tokens = vulu_token | commit_tokens
use_tokens = vulu_token & commit_tokens
waste_tokens = total_tokens - use_tokens
# print('total words: ',len(total_tokens))
# print('total useful words: ',len(use_tokens))
# print('total useful words',len(waste_tokens))
 
with open(tokenpath+'tokens_useful.txt', 'w+') as fp:
    fp.write(str(use_tokens))
with open(tokenpath+'tokens_unuseful.txt', 'w+') as fp:
    fp.write(str(waste_tokens))



### ==========  vuln token =====================

vuln_df = pd.read_csv("../data/vuln_data.csv")
vuln_df['cwedesc'] = vuln_df['cwedesc'].apply(lambda item:to_token(item, use_tokens))
vuln_df['desc'] = vuln_df['desc'].apply(lambda item:to_token(item, use_tokens))
vuln_df['total'] = vuln_df['cwedesc'] + vuln_df['desc']
vuln_df.to_csv("../data/vuln_data.csv", index = False)


### ==========  commit token =====================

def get_commit_token(input):
    #   repo, commit = input
    reponame, commit = input
    repo = git.Repo(gitrepo_path + reponame)

    with open(tokenpath+'tokens_useful.txt', 'r') as fp:
        tokens = eval(fp.read())

    temp_commit = repo.commit(commit)
    mess = temp_commit.message.replace('\r\n', ' ').replace('\n', ' ')
    mess = to_token(mess, tokens)

    filepaths, funcs,  codes = [], [], []
    outputs = repo.git.diff(
        commit + '~1', commit, ignore_blank_lines=True, ignore_space_at_eol=True).split('\n')
    for line in outputs:
        if line.startswith('diff  --git'):
            filepath = line.split(' ')[-1].strip()[2:] 
            filepaths.extend(to_token(filepath, tokens))
        elif line.startswith('@@ '):
            funcname = line.split('@@')[-1].strip()
            funcname = funcs_preprocess(funcname)
            funcs.extend(to_token(funcname, tokens))
        else:
            line_tokens = to_token(line[1:], tokens)
            codes.extend(line_tokens)

    total_token = union_list(mess, filepaths, funcs, codes)
    with open(gitcommit_path+'{}/{}'.format(reponame, commit), 'w') as fp:
        fp.write(str(total_token))
    return None
#   total_token = [item for item in total_token if item in tokens]
#   return total_token


def multi_process_get_commit_token(repo, commits):
    length=len(commits)
    with Pool(5) as p: 
        list(tqdm(p.imap(get_commit_token, zip([repo for i in range(length)], commits)) ,total=length,desc='多进程处理commits'))
        p.close() 
        p.join()


with open('../data/repo_commit.txt', 'r') as fp:
    repo_commits = eval(fp.read())

df = pd.read_csv('../data/data.csv')
repos = df.repo.unique()

for reponame in repos:
    logging.info(reponame+ '正在处理....')
    print(reponame+ '正在处理....')
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))

    repo_gitcommit_path = gitcommit_path+reponame
    if not os.path.exists(repo_gitcommit_path):
        os.makedirs(repo_gitcommit_path)

    repo = git.Repo(gitrepo_path + reponame)
    multi_process_get_commit_token(reponame, repo_commits[reponame])

# ===================== IDF =====================


from util import *
from glob import glob


npools = 5
df = pd.read_csv('../data/data.csv')
repos = df.repo.unique()

files = glob('/home/wangsc/Python/Vulnerability/gitcommit/*/*')
print('共有commit总数', len(files))


def get_commit_token(filepaths):
    token_dict = dict()
    for token in tokens:
        token_dict[token] = 0

    for file in tqdm(filepaths, ncols=80, desc='执行任务' + ' pid:' + str(os.getpid())):
        with open(file, 'r') as fp:
            commit_token = set(eval(fp.read()))
        for item in commit_token:
            token_dict[item] += 1
        del commit_token
        gc.collect()
    return token_dict


def multi_process_get_commit_token(file_list):
    length = len(file_list)
    with Pool(npools) as p:
        result = list(p.imap(get_commit_token, file_list))
        p.close()
        p.join()
    return result


length = len(files)
file_list = []
for i in range(npools):
    tmp = files[math.floor(i / npools * length)
                           :math.floor((i + 1) / npools * length)]
    file_list.append(tmp)
result = multi_process_get_commit_token(file_list)

token_dict = {}
for token in tokens:
    token_dict[token] = 0
for dic in tqdm(result):
    for token in dic.keys():
        token_dict[token] += dic[token]


def get_vuln_token(vuln_token):
    token_dict = {}
    for token in tokens:
        token_dict[token] = 0
    for token in tqdm(vuln_token, ncols=80, desc='执行任务' + ' pid:' + str(os.getpid())):
        for item in token:
            if item in tokens:
                token_dict[item] += 1
    return token_dict


def multi_process_get_vuln_token(vuln_tokens):
    length = len(vuln_tokens)
    with Pool(npools) as p:
        result = list(p.imap(get_vuln_token, vuln_tokens))
        p.close()
        p.join()
    return result


df = pd.read_csv('../data/vuln_data.csv')
df['total'] = df['total'].apply(eval)
vuln_tokens = list(df['total'])
# length_vuln = len(vuln_tokens)
# print(length_vuln)
vuln_commit = []
for i in range(npools):
    tmp = vuln_tokens[math.floor(
        i / npools * length_vuln):math.floor((i + 1) / npools * length_vuln)]
    vuln_commit.append(tmp)
result = multi_process_get_vuln_token(vuln_commit)

for dic in tqdm(result):
    for token in dic.keys():
        token_dict[token] += dic[token]

for item in token_dict.keys():
    token_dict[item] = np.log((len(files)+len(vulu_tokens)) / (token_dict[item]+1))

with open('../data/token_IDF.txt', 'w') as fp:
    fp.write(str(token_dict))
