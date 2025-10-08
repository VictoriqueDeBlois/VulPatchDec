# 导入os模块，用于操作文件和目录
import csv
import json
import os
import pickle
import re
from collections import defaultdict

import pandas as pd
from pandas import read_json

import config
from util.github_util import get_title_by_commit_hash

# 定义一个空列表，用于存储commit的hash值
repo_cannot_find_tracer_commit = []
pipeline_dir = config.PIPILINE_PATH

temp_files = []


def frequency_commits_accuracy(cves, map):
    not_include = set()
    for cve in cves:

        same_file = os.path.join(config.TEST_PATH, cve, "same_patch.csv")

        if not os.path.exists(same_file) or os.path.getsize(f'{config.TEST_PATH}{cve}/same_patch.csv') == 0:
            print(f'{cve} same_patch.csv is empty')
            with open(f'{config.current_dir}/test_cve_not_include_commit.txt', 'a') as f:
                f.write(cve + '\n')
            continue
        with open(same_file, "r") as f:
            reader = csv.reader(f)
            flag = False
            if cve not in map:
                print(f'{cve} not in map')
                continue
            for link in map[cve]:
                m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', link)
                if m == None:
                    continue
                owner = m.group(1)
                repo = m.group(2)
                hash = m.group(3)
                title = get_title_by_commit_hash(hash, f'{config.GIT_REPO_PATH}{owner}/{repo}')
                try:
                    for line in reader:
                        try:
                            if len(line) < 3:
                                continue

                            if line[0] in hash or hash in line[0] or hash in line[1] or line[1] in hash or line[
                                2] == title:
                                flag = True
                        except:
                            continue
                except:
                    continue
        if flag is True:
            with open(f'{config.current_dir}/FinaltestCve.txt', 'a') as f:
                f.write(cve + '\n')
        else:
            print(f'{cve} same_patch.csv  not include benchline  commit ')
            with open(f'{config.current_dir}/test_cve_not_include_benchline_commit.txt', 'a') as f:
                f.write(cve + '\n')


def frequency_commits_accuracy_v2(cves):
    not_include = set()
    for cve in cves:

        same_file = os.path.join(config.TEST_PATH, cve, "same_patch.csv")

        if not os.path.exists(same_file) or os.path.getsize(f'{config.TEST_PATH}{cve}/same_patch.csv') == 0:
            print(f'{cve} same_patch.csv is empty')
            with open(f'{config.current_dir}/test_cve_not_include_commit.txt', 'a') as f:
                f.write(cve + '\n')
            continue
        map = {}

        with open(f'../pythonProject/CVEKnowledgeMap/resource/vera.csv', "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if cve == row[0]:
                    map[cve] = set()
                    fixed_version = row[1]
                    commit = row[2]
                    map[cve].add(commit)
                    break
        with open(same_file, "r") as f:
            reader = csv.reader(f)
            flag = False
            if cve not in map:
                print(f'{cve} not in map')
                continue
            for link in map[cve]:
                m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', link)
                if m == None:
                    continue
                owner = m.group(1)
                repo = m.group(2)
                hash = m.group(3)
                title = get_title_by_commit_hash(hash, f'{config.GIT_REPO_PATH}{owner}/{repo}')

                for line in reader:
                    if line.__len__() < 3:
                        continue

                    if line[0] in hash or hash in line[0] or hash in line[1] or line[1] in hash or line[2] == title:
                        flag = True
        if flag is True:
            with open(f'{config.current_dir}/FinaltestCve.txt', 'a') as f:
                f.write(cve + '\n')
        else:
            not_include.add(cve)

    for cve in not_include:
        # 删除test目录下的目录
        os.system(f'rm -rf {config.TEST_PATH}{cve}')


def TracerRecall(cves, map):
    count = 0
    accuracy = 0
    for cve in cves:
        if cve + ".txt" not in os.listdir(config.TRACER_COMMIT_PATH):
            continue
        dict = []

        # 获取文件的完整路径

        file_path = os.path.join(config.TRACER_COMMIT_PATH, cve + ".txt")
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            print(f'{cve} not found')
            continue
        count += 1
        with open(file_path, "r") as f:
            # 逐行读取文件内容
            for line in f:
                # 去掉行尾的换行符
                line = line.strip()
                m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', line)
                if m is None:
                    continue
                owner = m.group(1)
                repo = m.group(2)
                sha = m.group(3)
                # 将行内容作为commit的hash值，添加到列表中
                title = get_title_by_commit_hash(sha, f'{config.GIT_REPO_PATH}{owner}/{repo}')
                dict.append([sha, title])
        if dict.__len__() == 0:
            continue
        benchline = []
        if cve not in map:
            print(f'{cve} not in map')
            count -= 1
            continue
        for link in map[cve]:
            m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', link)
            if m == None:
                continue
            owner = m.group(1)
            repo = m.group(2)
            hash = m.group(3)
            title = get_title_by_commit_hash(hash, f'{config.GIT_REPO_PATH}{owner}/{repo}')
            benchline.append([hash, title])

        flag = False
        correct = 0

        for d in dict:
            if d is None:
                continue
            flag = False
            for i in benchline:
                if i[0] in d[0] or d[0] in i[0] or d[1] == i[1]:
                    flag = True
                    correct += 1

                if flag:
                    break
        accuracy = accuracy + min(correct / benchline.__len__(), 1)
    print(count)
    print(accuracy / count)


def TracerAccuracy(cves, map):
    count = 0
    accuracy = 0
    correct_count = 0
    for cve in cves:
        if cve + ".txt" not in os.listdir(config.TRACER_COMMIT_PATH):
            continue
        dict = []

        # 获取文件的完整路径
        file_path = os.path.join(config.TRACER_COMMIT_PATH, cve + ".txt")
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            # print(f'{cve} not found')
            continue
        with open(file_path, "r") as f:
            # 逐行读取文件内容
            for line in f:
                # 去掉行尾的换行符
                line = line.strip()
                m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', line)
                if m is None:
                    continue
                owner = m.group(1)
                repo = m.group(2)
                sha = m.group(3)
                # 将行内容作为commit的hash值，添加到列表中
                title = get_title_by_commit_hash(sha, f'{config.GIT_REPO_PATH}{owner}/{repo}')
                dict.append([sha, title])
        count += 1
        if dict.__len__() == 0:
            continue
        benchline = []
        if cve not in map:
            # print(f'{cve} not in map')
            count -= 1
            continue
        for link in map[cve]:
            m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', link)
            if m == None:
                continue
            owner = m.group(1)
            repo = m.group(2)
            hash = m.group(3)
            title = get_title_by_commit_hash(hash, f'{config.GIT_REPO_PATH}{owner}/{repo}')
            benchline.append([hash, title])

        flag = False
        correct = 0

        for d in dict:
            if d is None:
                continue
            flag = False
            for i in benchline:
                if i[0] in d[0] or d[0] in i[0] or d[1] == i[1]:
                    with open(f'../tracer_correctCve.txt', 'a') as f:
                        f.write(cve + '\n')
                    flag = True
                    correct += 1

                if flag:
                    break
        if correct != 0:
            correct_count += 1
            if 'CVE-2024' in cve:
                print(f'{cve}')

        accuracy = accuracy + correct / dict.__len__()
    print(count)
    print(correct_count)
    print(accuracy / count)


def VulAccuracy_By_Fre(cves, map, fre):
    count = 0
    len = 0
    correct_count = 0
    for cve in cves:
        dict = []
        pkl_file = os.path.join(pipeline_dir, cve, f'answer_prompt_by_fre_{fre}.pkl')
        if not os.path.exists(pkl_file):
            # print(f'{cve} not found')
            continue
        with open(pkl_file, 'rb') as file:
            answer_commits = pickle.load(file)
        if cve not in map:
            # print(f'{cve} not in map')
            continue
        if answer_commits.__len__() == 0:
            # print(f'{cve} answer_commits is empty')
            continue
        for link in map[cve]:
            m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', link)
            if m == None:
                continue
            owner = m.group(1)
            repo = m.group(2)
            hash = m.group(3)
            title = get_title_by_commit_hash(hash, f'{config.GIT_REPO_PATH}{owner}/{repo}')
            dict.append([hash, title])
        flag = False
        correct = 0
        len += 1
        with open(f'{config.RESOURCE_PATH}/cve_has_answer.txt', 'a') as f:
            f.write(cve + '\n')
        for commit in answer_commits:
            if commit is None:
                continue
            for i in dict:
                if i[0] in commit[0] or commit[0] in i[0] or i[0] in commit[1] or commit[1] in i[0] or commit[2] == i[
                    1]:
                    flag = True
                    correct += 1
                    break

        if flag:
            # with open(f'{config.current_dir}/resource/VulcorrectCve.txt', 'a') as f:
            #     f.write(cve + '\n')
            correct_count = correct_count + 1
            if 'CVE-2024' in cve:
                print(f'{cve}')

        count = count + correct / answer_commits.__len__()
    print(len)
    print(correct_count)
    print(count / len)
    print(count / 684)


def VulAccuracy(cves, map):
    count = 0
    len = 0
    correct_count = 0

    cve_has_answer = []
    cve_correct_answer = []

    for cve in cves:
        dict = []
        pkl_file = os.path.join(pipeline_dir, cve, 'answer_prompt.pkl')

        if not os.path.exists(pkl_file):
            # print(f'{cve} not found')
            continue
        with open(pkl_file, 'rb') as file:
            answer_commits = pickle.load(file)
        frequency = 0
        reader = pd.read_csv(f'{pipeline_dir}{cve}/frequecy.csv', header=None)
        if reader.loc[0, 0] == cve:
            frequency = reader.loc[0, 2]
        if cve not in map:
            # print(f'{cve} not in map')
            continue
        if answer_commits.__len__() == 0:
            # print(f'{cve} answer_commits is empty')
            continue
        for link in map[cve]:
            m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', link)
            if m == None:
                continue
            owner = m.group(1)
            repo = m.group(2)
            hash = m.group(3)
            title = get_title_by_commit_hash(hash, f'{config.GIT_REPO_PATH}{owner}/{repo}')
            dict.append([hash, title])
        flag = False
        correct = 0
        len += 1
        cve_has_answer.append(cve)
        # with open(f'{config.RESOURCE_PATH}/cve_has_answer.txt', 'a') as f:
        #     f.write(cve + '\n')
        for commit in answer_commits:
            if commit is None:
                continue
            for i in dict:
                if i[0] in commit[0] or commit[0] in i[0] or i[0] in commit[1] or commit[1] in i[0] or commit[2] == i[
                    1]:
                    flag = True
                    correct += 1
                    break

        if flag:
            cve_correct_answer.append((cve, frequency))
            correct_count = correct_count + 1
            if int(frequency) < 5:
                print(f'{cve}')
        count = count + correct / answer_commits.__len__()
    print(len)
    print(correct_count)
    print(count / len)


def VulRecall_By_Fre(cves, map, fre):
    count = 0
    len = 0
    correct_count = 0
    for cve in cves:
        dict = []
        pkl_file = os.path.join(pipeline_dir, cve, f'answer_prompt_by_fre_{fre}.pkl')
        if not os.path.exists(pkl_file):
            # print(f'{cve} not found')
            continue
        with open(pkl_file, 'rb') as file:
            answer_commits = pickle.load(file)
        if cve not in map:
            # print(f'{cve} not in map')
            continue
        if answer_commits.__len__() == 0:
            # print(f'{cve} answer_commits is empty')
            continue
        for link in map[cve]:
            m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', link)
            if m == None:
                continue
            owner = m.group(1)
            repo = m.group(2)
            hash = m.group(3)
            title = get_title_by_commit_hash(hash, f'{config.GIT_REPO_PATH}{owner}/{repo}')
            dict.append([hash, title])
        flag = False
        correct = 0
        len += 1
        for commit in answer_commits:
            if commit is None:
                continue
            for i in dict:
                if i[0] in commit[0] or commit[0] in i[0] or i[0] in commit[1] or commit[1] in i[0] or commit[2] == i[
                    1]:
                    flag = True
                    correct += 1

            if flag:
                count = count + min(1, correct / dict.__len__())
                break
    print(len)
    print(correct_count)
    print(count / len)


def VulRecall(cves, map):
    count = 0
    len = 0
    correct_count = 0
    for cve in cves:
        dict = []
        pkl_file = os.path.join(pipeline_dir, cve, 'answer_prompt.pkl')
        if not os.path.exists(pkl_file):
            print(f'{cve} not found')
            continue
        with open(pkl_file, 'rb') as file:
            answer_commits = pickle.load(file)
        if cve not in map:
            print(f'{cve} not in map')
            continue
        if answer_commits.__len__() == 0:
            print(f'{cve} answer_commits is empty')
            continue
        for link in map[cve]:
            m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', link)
            if m == None:
                continue
            owner = m.group(1)
            repo = m.group(2)
            hash = m.group(3)
            title = get_title_by_commit_hash(hash, f'{config.GIT_REPO_PATH}{owner}/{repo}')
            dict.append([hash, title])
        flag = False
        correct = 0
        len += 1
        for commit in answer_commits:
            if commit is None:
                continue
            for i in dict:
                if i[0] in commit[0] or commit[0] in i[0] or i[0] in commit[1] or commit[1] in i[0] or commit[2] == i[
                    1]:
                    flag = True
                    correct += 1

            if flag:
                count = count + min(1, correct / dict.__len__())
                break
    print(len)
    print(correct_count)
    print(count / len)


def VulAccuracy_part4(cves, map):
    count = 0
    len = 0
    correct_count = 0
    for cve in cves:
        dict = []
        pkl_file = os.path.join('../pythonProject/CVEKnowledgeMap/temp_pipline', cve, 'answer_prompt.pkl')
        if not os.path.exists(pkl_file):
            print(f'{cve} not found')
            continue
        with open(pkl_file, 'rb') as file:
            answer_commits = pickle.load(file)
        if cve not in map:
            print(f'{cve} not in map')
            continue
        if answer_commits.__len__() == 0:
            print(f'{cve} answer_commits is empty')
            continue
        for link in map[cve]:
            m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', link)
            if m == None:
                continue
            owner = m.group(1)
            repo = m.group(2)
            hash = m.group(3)
            title = get_title_by_commit_hash(hash, f'{config.GIT_REPO_PATH}{owner}/{repo}')
            dict.append([hash, title])
        flag = False
        correct = 0
        len += 1
        with open(f'{config.RESOURCE_PATH}/cve_has_answer.txt', 'a') as f:
            f.write(cve + '\n')
        for commit in answer_commits:
            if commit is None:
                continue
            for i in dict:
                if i[0] in commit[0] or commit[0] in i[0] or i[0] in commit[1] or commit[1] in i[0] or commit[2] == i[
                    1]:
                    flag = True
                    correct += 1
                    break

        if flag:
            with open(f'{config.current_dir}/resource/VulcorrectCve.txt', 'a') as f:
                f.write(cve + '\n')
            correct_count = correct_count + 1
        else:
            print(f'{cve}')
        count = count + correct / answer_commits.__len__()
    print(len)
    print(correct_count)
    print(count / len)


def get_overlap(cves):
    # 得到vul有但是TRACER没有的
    with open(f'../wrongCve.txt', 'r') as f:
        wrongCveVul = f.readlines()
        wrongCveVul = [x.strip() for x in wrongCveVul]
        wrongCveVul = set(wrongCveVul)
    correct = set(cves) - wrongCveVul
    with open(f'../tracer_correctCve.txt', 'r') as f:
        tracer_correctCve = f.readlines()
        tracer_correctCve = [x.strip() for x in tracer_correctCve]
        tracer_correctCve = set(tracer_correctCve)
    overlap = correct & tracer_correctCve
    nonoverlapVul = correct - tracer_correctCve
    nonoverlapTracer = tracer_correctCve - correct
    print(overlap)
    # print(nonoverlapVul)
    # print(nonoverlapVul.__len__())
    # print(nonoverlapTracer)
    # print(nonoverlapTracer.__len__())


def metrics(cves, bench):
    cve_has_answer = []
    cve_correct_answer = []

    for cve in cves:
        pkl_file = os.path.join(pipeline_dir, cve, 'answer_prompt.pkl')
        if not os.path.exists(pkl_file):
            continue
        with open(pkl_file, 'rb') as file:
            answer_commits = pickle.load(file)
        frequency = 0
        reader = pd.read_csv(f'{pipeline_dir}{cve}/frequecy.csv', header=None)
        if reader.loc[0, 0] == cve:
            frequency = reader.loc[0, 2]
        if cve not in map:
            continue
        if len(answer_commits) == 0:
            continue
        cve_has_answer.append(cve)


        standard = []
        for link in bench[cve]:
            m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', link)
            if m is None:
                continue
            owner = m.group(1)
            repo = m.group(2)
            commit_hash = m.group(3)
            title = get_title_by_commit_hash(commit_hash, f'{config.GIT_REPO_PATH}{owner}/{repo}')
            # standard[link] = (owner, repo, commit_hash, title)
            standard.append([commit_hash, title])

        flag = False
        correct = 0

        answer = {}
        for commit in answer_commits:
            if commit is None:
                continue
            for i in standard:
                if i[0] in commit[0] or commit[0] in i[0] or i[0] in commit[1] or commit[1] in i[0] or commit[2] == i[
                    1]:
                    flag = True
                    correct += 1
                    break

        if flag:
            cve_correct_answer.append((cve, frequency))
            correct_count = correct_count + 1
            if int(frequency) < 5:
                print(f'{cve}')
        count = count + correct / answer_commits.__len__()
    print()

# accurate_patch_cves_82 = []
if __name__ == "__main__":
    # todo 数据源的数据
    # with open(f'{config.RESOURCE_PATH}dataset2.txt', 'r') as f:
    #     cves = f.readlines()
    #     cves = [x.strip() for x in cves]
    # answers = os.listdir('../pythonProject/CVEKnowledgeMap/answer')
    # # with open(f'{config.RESOURCE_PATH}/dataset1.txt', 'r') as f:
    # #     cves = f.readlines()
    # #     cves = [x.strip() for x in cves]
    # cves = [x for x in cves if x  in answers]

    # todo benchline的数据
    bench = {}
    with open("../resource/depth_dataset.csv", 'r') as f:
        reader = csv.reader(f)
        # 跳过第一行
        next(reader)

        for row in reader:
            key = row[0]
            value = row[3]

            if not 'CVE-' in key or value == '':
                continue
            if key in bench:
                bench[key].append(value)
            else:
                bench[key] = [value]

    # 读取vera.csv
    with open(f'../pythonProject/CVEKnowledgeMap/resource/vera.csv', "r") as f:
        reader = csv.reader(f)
        for row in reader:
            key = row[0]
            value = row[2]
            if not 'CVE-' in key or value == '':
                continue
            if key in bench:
                bench[key].append(value)
            else:
                bench[key] = [value]

    with open('../pythonProject/CVEKnowledgeMap/resource/brench.json', "w", encoding='utf-8') as fp:
        json.dump(bench, fp, indent=4)

    # TRACER_COMMIT__META_PATH = os.listdir(config.TRACER_COMMIT__META_PATH)
    # with open(f'{config.current_dir}resource/VulcorrectCve_part3.txt', 'r') as f:
    #     vulCorrectCVE = f.readlines()
    #     vulCorrectCVE = [x.strip() for x in vulCorrectCVE]
    # answers = os.listdir(f'{config.ANSWER_PATH}')
    # cves = set(answers)
    # with open (f'{config.RESOURCE_PATH}/main_language_cve.csv', 'r') as f:
    #     cves = f.readlines()
    #     cves = [x.strip() for x in cves]
    with open(f'{config.RESOURCE_PATH}FinaltestCve.txt', 'r') as f:
        cves = f.readlines()
        cves = [x.strip() for x in cves]
    cves = set(cves)
    cves = list(cves)
    cves = sorted(cves)
    # for cve in cves:
    #     if 'CVE-2024' not in cve:
    #         continue
    #     data.add(cve)
    # for fre in [0,5,7]:
    #     # VulAccuracy_By_Fre(cves,map,fre)
    #     VulRecall_By_Fre(cves,map,fre)
    # VulAccuracy(cves, map)
    # cves = os.listdir(config.TEST_PATH)
    # TracerAccuracy(cves, map)

    hash_len = defaultdict(list)
    for i in bench.values():
        for link in i:
            commit_hash = link.split('/')[-1]
            hash_len[len(commit_hash)].append(link)
    
    metrics(cves, bench)
    # TracerRecall(data,map)
    # VulRecall(cves,map)

    # todo 测试提交的召回率
    # with open(f'{config.current_dir}/resource/VulcorrectCve.txt', 'r') as f:
    #     cves = f.readlines()
    #     cves = [x.strip() for x in cves]
    # cves = set(cves)

    # divide(os.listdir(config.TEST_PATH),map)

    # 漏洞的正确性
    # VulAccuracyCVE(cves,map)
    # cves = map.keys()
    # 准确率、召回率
    # TracerAccuracyCVE(cves,map)
    # TracerRecall(cves,map)

    # with open(f'../tracer_correctCve.txt', 'r') as f:
    #     correct = f.readlines()
    #     correct = [x.strip() for x in correct]
    #     correct = set(correct)
    # print(correct.__len__()/cves.__len__())

    # todo 得到重复的以及不同的
    # get_overlap(os.listdir(config.PIPILINE_PATH))

    # todo part_4的正确率
    # VulAccuracy(cves,map)

    # 分母是answer的CVE数量

    # #读取wrongCvE，得到所有的错误的cve
    # with open(f'{config.current_dir}/wrongCve.txt', 'r') as f:
    #     wrongCve = f.readlines()
    # wrongCve = [x.strip() for x in wrongCve]
    # #得到正确的cve
    # correctCve = [x for x in cves if x not in wrongCve]
    # print(len(correctCve))
    # print(len(cves))
    # accuracy = len(correctCve)/len(cves)
    # print(accuracy)
