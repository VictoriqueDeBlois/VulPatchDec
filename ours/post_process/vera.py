import csv
import json
import os
import re

import config
from util.vera_util import get_vera_found

def get_cve_list():
    with open("../VulnerCollector/data/dataset/breadth_dataset-DBB_CVEIDs_withPatches.json", "r") as f:
        data1 = json.load(f)
        f.close()
    # 获取字典键并存储在一个列表中
    keys1 = list(data1.keys())
    return keys1




# def get_Tracer_commits(cve):


if __name__ == "__main__":
    # cve_list = get_cve_list()
    cve_list = os.listdir("../pythonProject/CVEKnowledgeMap/answer")
    vera_count = 0
    for cve in cve_list:
        print(cve)
        # if f'{cve}.csv' in os.listdir(config.TRACCER_NOT_MATHCED_PATH):
        #     continue
        version_commits = get_vera_found(cve)
        if version_commits.__len__() == 0:
            continue
        repo_file = open(f'{config.OUTPUT_PATH}{cve}/repo_config.csv', "r")
        reader = csv.reader(repo_file)
        first_row = next(reader)
        owner = first_row[0]
        repo = first_row[1]
        if not os.path.exists(f'{config.RESULT_PATH}{cve}/commit1.csv'):
            continue
        commits_csv = open(f'{config.RESULT_PATH}{cve}/commit1.csv', "r")
        reader = csv.reader(commits_csv)
        answer_commits = set()

        for row in reader:
            # commit hash
            answer_commits.add(row[0])
        tag = True

        for fixed_version in version_commits:
            commits = version_commits[fixed_version]
            if commits.__len__() == 0:
                continue
            for commit in commits:
                if commit == None:
                    continue
                m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', commit)
                if m == None:
                    continue
                hash = m.group(3)

                if hash not in answer_commits:
                    tag =False
                    with open(f'../pythonProject/CVEKnowledgeMap/cve/compare_answer/{cve}.csv', 'a+') as f:
                        writer = csv.writer(f)
                        writer.writerow([fixed_version, commit])
                        f.close()
                    vera_count += 1


        if tag:
            print("True: "+cve)
        print(str(vera_count))
    # print("找不到vera提供commit 的个数是:" + vera_count)
