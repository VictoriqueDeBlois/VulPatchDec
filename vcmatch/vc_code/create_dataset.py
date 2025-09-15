import git
import numpy as np
import pandas as pd
import time
import os
import random
from tqdm import tqdm


if __name__ == '__main__':
    df = pd.read_csv('../data/data.csv')
    repos = df.repo.unique()
    repo_commit = dict()
    for reponame in repos:
        t1 = time.time()
        repo = git.Repo('../gitrepo/{}'.format(reponame))
        total_commits = [str(item) for item in repo.iter_commits()]
        commits = []
        for commit in total_commits:
            try:
                repo.git.diff(commit+ '~1', commit)
                commits.append(commit)
            except:
                pass
        t2 = time.time()
        repo_commit[reponame] = commits

    with open('../data/repo_commit.txt', 'w') as fp:
        fp.write(str(repo_commit))

    iters = 5000
    total_data = []
    for cve in df.groupby('cve'):
        cve_id = cve[0]
        reponame = list(cve[1].repo.unique())[0]
        pos_commit = list(cve[1].commit.unique())[0]
        neg_commits = []
        np.random.shuffle(repo_commit[reponame])
        cnt = 0
        for commit in commits:
            if cnt >= neg_num: break
            if commit == pos_commit:
                break
            else:
                neg_commits.append(commit)
                cnt += 1
        total_data.append([cve_id, reponame, commit, neg_commits])

    dataset = []
    for item in total_data:
        dataset.append([item[0], item[1], item[2], item[2], 1])
        for commit in item[3]:
            dataset.append([item[0], item[1], item[2], commit, 0])

    df = pd.DataFrame(dataset, columns = ['cve', 'repo', 'true_commit', 'commit', 'label'])
    df.to_csv('../data/Dataset_5000.csv', index = False)