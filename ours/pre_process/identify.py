import os
import csv
import re

import config
from  util.vera_util import get_vera_found
not_include = os.listdir("/data/zy/pythonProject/CVEKnowledgeMap/cve/compare_answer")
count_has = 0
cout_not = 0
res = []
not_cve = set()

for file in not_include:
    cve =file.replace(".csv","")
    vera_count = 0
    # print(cve)
    # if f'{cve}.csv' in os.listdir(config.TRACCER_NOT_MATHCED_PATH):
    #     continue
    version_commits = get_vera_found(cve)
    same_file = open(f'{config.TEST_PATH}{cve}/same_patch.csv', "r")
    reader = csv.reader(same_file)
    rows = list(reader)
    repo_file = open(f'{config.TEST_PATH}{cve}/repo_config.csv', "r")
    reader = csv.reader(repo_file)
    first_row = next(reader)
    owner = first_row[0]
    repo = first_row[1]
    if rows.__len__() == 0:
        # print("same_commit length = 0:"+cve)
        cout_not += 1
        continue
    hashs = set()
    for row in rows:
        hashs.add(row[0])
    commits_csv = open(f'/data/zy/pythonProject/CVEKnowledgeMap/result_same_50/{cve}/commit1.csv', "r")
    reader = csv.reader(commits_csv)
    answer_commits = set()
    for row in reader:
        # commit hash
        answer_commits.add(row[0])
    tag = True
    for commits in version_commits.values():

        if commits == None:
            continue
        for commit in commits:
            if commit == None:
                continue
            m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', commit)
            if m == None:
                continue
            hash = m.group(3)
            if hash not in hashs:
                # print(cve)
                tag = False
                cout_not += 1
                not_cve.add(cve)
                break
        if not tag:
            break
    if tag:
        count_has += 1
        res.append(cve)
# print(res)
print(not_cve)
print(cout_not)
print(count_has)

