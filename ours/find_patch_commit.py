import csv
import os
import pickle
import random
import shutil

import openai

import config
from check_data import read_cve_file
# from util.ask_GPT import ask_patch_commit
from util.cve_parser import get_cve_description
# from util.tool import get_numbers_with_hash, check_cve, check_pr, get_numbers_with_answer

openai.api_key = "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"


def make_prompt(cveid, description, commits, patch_commits_messages, cve_issue, cve_pr):
    example_file = open(os.path.join('/data/zy/pythonProject/CVEKnowledgeMap/example_prompt'), "r")
    example_prompt = example_file.read()
    example_file.close()
    prompt = (
        f'Please help me find the best  commit patches (up to five)  for fixing the vulnerability step by step and only give the reasoning process why this(those)  commit(s) is(are) patch commit ,'
        f'answer simplifily  and only say the main points. \n'
        f'{example_prompt}\n'
        f'Q:\n'
        f'CVEID: {cveid}'
        f'CVE Description: {description}, \n'
        f'Commit Information: {commits}, numbered from 0,')
    if cve_issue.get(cveid) is not None:
        prompt = prompt + f' and the issue id that may contain the CVE identifier is {cve_issue.get(cveid)}.'
    if cve_pr.get(cveid) is not None:
        prompt = prompt + f' and the pull request id that may contain the CVE identifier is {cve_pr.get(cveid)}.'
    if patch_commits_messages.__len__() != 0:
        message = ""
        for m in patch_commits_messages:
            message = f'{message} / {m}'
        prompt = prompt + f' and the patch commit messages that we found are {patch_commits_messages}.'
    print(prompt)
    return prompt


count = 0


def get_patch_commits(file, folder):
    cve = folder
    cve_issue = {}
    cve_pr = {}
    candidate_commits = {}
    patch_commits = {}
    patch_hash = set()
    # 读取repo_config.csv文件
    if not os.path.exists(f'{config.TEST_PATH}{folder}/repo_config.csv'):
        print(f'{folder} repo_config.csv is None')
        return None
    repo_file = open(f'{config.TEST_PATH}{folder}/repo_config.csv', "r")
    reader = csv.reader(repo_file)
    first_row = next(reader)
    owner = first_row[0]
    repo = first_row[1]
    # file = open(f'/data/zy/pythonProject/CVEKnowledgeMap/output/CVE-2020-9548/same_patch.csv', "r")

    reader = csv.reader(file)

    # 遍历reader对象，获取每一行的长度
    rows = []
    # 如果csv模块的字段超过最大长度

    csv.field_size_limit(10000000)
    # 遍历reader对象，尝试读取每一行
    for row in reader:
        try:
            if row.__len__() > 2 and row[2].__len__() < 1000 and row.__len__() > 3 and row[3].__len__() < 1000:
                # 将每一行添加到rows列表中
                rows.append(row)
            # print(row)
        except UnicodeDecodeError:
            pass

    description = get_cve_description(cve)

    # if num > 50:
    #     mylogger.warning("commit数量>50的 cve编号是" + cve)
    #     continue

    # if not os.path.exists(config.PIPILINE_PATH + cve):
    for line in rows:
        # todo Assume : All Fix #123 is issue id //后续处理等效数据集修改
        # todo PR 的#id
        candidate_commits[candidate_commits.__len__()] = line

        # if "#" in line[2]:
        #     ids = get_numbers_with_hash(line[2], "#")
        #     for i in ids:
        #         if cve_issue.get(cve) is None or i not in cve_issue.get(cve):
        #             # issue page find cve identifier
        #             check_res = check_cve(owner, repo, i, cve)
        #             if check_res is True:
        #                 if cve_issue.get(cve) is None:
        #                     cve_issue[cve] = [f'#{i}']
        #                 else:
        #                     cve_issue.get(cve).append(f'#{i}')
        #                 if patch_hash.__contains__(line[0]):
        #                     continue
        #                 patch_commits[patch_commits.__len__()] = line
        #                 patch_hash.add(line[0])
        #                 if not os.path.exists(f'{config.RESULT_PATH}{folder}'):
        #                     os.makedirs(f'{config.RESULT_PATH}{folder}')
        #                 file = open(os.path.join(f'{config.RESULT_PATH}{folder}/commit1.csv'), "a+")
        #                 writer = csv.writer(file)
        #                 writer.writerow(line)
        #                 file.close()
        #                 print(f'find {cve} identifier issue id {i} in {line[2]}')
        #                 candidate_commits[candidate_commits.__len__()] = line
        #
        #             elif check_res is False:
        #                 candidate_commits[candidate_commits.__len__()] = line
        #             elif check_res is None:
        #                 #  find another cve identifier
        #                 pass
        #             elif check_res == 404:
        #                 # 404 not issue page find pr page
        #                 if cve_pr.get(cve) is None or i not in cve_pr.get(cve):
        #                     # issue page find cve identifier
        #                     check_res = check_pr(owner, repo, i, cve)
        #                     if check_res is True:
        #                         if cve_pr.get(cve) is None:
        #                             cve_pr[cve] = [f'#{i}']
        #                         else:
        #                             cve_pr.get(cve).append(f'#{i}')
        #                         if patch_hash.__contains__(line[0]):
        #                             continue
        #                         patch_commits[patch_commits.__len__()] = line
        #                         patch_hash.add(line[0])
        #                         if not os.path.exists(f'{config.RESULT_PATH}{folder}'):
        #                             os.makedirs(f'{config.RESULT_PATH}{folder}')
        #                         file = open(os.path.join(f'{config.RESULT_PATH}{folder}/commit1.csv'), "a+")
        #                         writer = csv.writer(file)
        #                         writer.writerow(line)
        #                         file.close()
        #                         print(f'find {cve} identifier pr id {i} in {line[2]}')
        #                     elif check_res is False:
        #                         candidate_commits[candidate_commits.__len__()] = line
        #                     elif check_res is None:
        #                         #  find another cve identifier
        #                         pass
        #                     elif check_res == 404:
        #                         candidate_commits[candidate_commits.__len__()] = line
        #
        #
        # else:
        #     candidate_commits[candidate_commits.__len__()] = line
        if not os.path.exists(config.PIPILINE_PATH + cve):
            os.makedirs(config.PIPILINE_PATH + cve)
            # with open(f'{config.PIPILINE_PATH}{cve}/cve_issue.pkl', 'wb') as f:
            #     pickle.dump(cve_issue, f)
            # with open(f'{config.PIPILINE_PATH}{cve}/cve_pr.pkl', 'wb') as f:
            #     pickle.dump(cve_pr, f)
            # with open(f'{config.PIPILINE_PATH}{cve}/candidate_commits.pkl', 'wb') as f:
            #     pickle.dump(candidate_commits, f)
            # with open(f'{config.PIPILINE_PATH}{cve}/patch_commits.pkl', 'wb') as f:
            #     pickle.dump(patch_commits, f)
    if candidate_commits.__len__() == 0:
        print(f'{folder} candidate_commits is None')
        return None
    test_commits_message = []
    # 获取patch_commit的message信息
    patch_commits_message = set()
    if patch_commits.__len__() != 0:
        for commit in patch_commits.values():
            patch_commits_message.add(commit[2])
            if commit[3] is not None:
                patch_commits_message.add(commit[3])

    # if candidate_commits.__len__() > 50:
    # #
    #     for i in candidate_commits.keys():
    #         commit = candidate_commits.get(i)
    #
    #         if i == candidate_commits.__len__() - 1:
    #             test_commits_message.append((i, commit[-1]))
    #             prompt = make_prompt(cve, description, test_commits_message, patch_commits_message, cve_issue,
    #                                  cve_pr)
    #             ans = ask_patch_commit(prompt)
    #             # ans ="1"
    #             numbers = get_numbers_with_answer(ans)
    #             if numbers.__len__() == 0:
    #                 file = open('no_number_answer.csv', 'a+')
    #                 file.write(folder)
    #                 file.close()
    #             else:
    #                 for num in numbers:
    #                     if num is None or num >= candidate_commits.__len__():
    #                         continue
    #                     if not os.path.exists(f'{config.RESULT_PATH}{folder}'):
    #                         os.makedirs(f'{config.RESULT_PATH}{folder}')
    #                     file = open(os.path.join(f'{config.RESULT_PATH}{folder}/commit.csv'), "a+")
    #                     writer = csv.writer(file)
    #
    #                     writer.writerow(candidate_commits.get(num))
    #                     file.close()
    #
    #         elif test_commits_message.__len__() == 50:
    #             test_commits_message.append((i, commit[-1]))
    #
    #             prompt = make_prompt(cve, description, test_commits_message, patch_commits_message, cve_issue,
    #                                  cve_pr)
    #             ans = ask_patch_commit(prompt)
    #             numbers = get_numbers_with_answer(ans)
    #             test_commits_message.clear()
    #             if numbers.__len__() == 0:
    #                 file = open('no_number_answer.csv', 'a+')
    #                 file.write(folder)
    #                 file.close()
    #
    #
    #             else:
    #                 for num in numbers:
    #                     if num is None or num >= candidate_commits.__len__():
    #                         continue
    #                     numbers.append(num)
    #                     test_commits_message.append((num, candidate_commits.get(num)[-1]))
    #
    #
    #
    #
    #
    #         else:
    #             test_commits_message.append((i, commit[-1]))
    #         # except Exception as e:
    #         #     file = open('no_number_answer.csv', 'a+')
    #         #     file.write(folder)
    #         #     file.close()
    #         #     print(
    #         #         f'{folder} {cve} {test_commits_message} {patch_commits_message}  numbers is None {e} ')
    #
    # else:
    # 继续先测行数<50的,直到100个回答
    if candidate_commits.__len__() < 50:

        for i in candidate_commits.keys():
            commit = candidate_commits.get(i)
            if commit[3].__len__() == 0:
                test_commits_message.append((i, commit[2]))
            else:
                test_commits_message.append((i, commit[2],commit[3]))

        prompt = make_prompt(cve, description, test_commits_message, patch_commits_message, cve_issue, cve_pr)

        # ans = ask_patch_commit(prompt)
        print()
        ans = None
        # numbers = get_numbers_with_answer(ans)
        # if numbers.__len__() == 0:
        #     file = open('no_number_answer.csv', 'a+')
        #     file.write(folder)
        #     file.close()
        # else:
        #     if not os.path.exists(f'{config.RESULT_PATH}{folder}'):
        #         os.makedirs(f'{config.RESULT_PATH}{folder}')
        if not os.path.exists(f'{config.ANSWER_PATH}{folder}'):
            os.makedirs(f'{config.ANSWER_PATH}{folder}')
            # with open(os.path.join(f'{config.ANSWER_PATH}{folder}/prompt.txt'), "w") as f:
            #     f.write(prompt)
        index = os.listdir(f'{config.ANSWER_PATH}{folder}').__len__()
        # with open(os.path.join(f'{config.ANSWER_PATH}{folder}/answer{index}.txt'), "w") as f:
        #     f.write(ans)
        # file.write(ans)
    file.close()


def get_commits_files(folders):
    # index从5到9

    for index in range(1, 11):
        for folder in folders:
            # # 获取文件夹下的其他csv文件
            # files = os.listdir(config.TEST_PATH + folder)[
            #todo 不存在same_patch.csv的原因？
            if not os.path.exists(os.path.join(f'{config.TEST_PATH}{folder}/same_patch.csv')):
                continue
            same_file = open(os.path.join(f'{config.TEST_PATH}{folder}/same_patch.csv'), "r", errors='ignore')
            # 判断same_file是否为空

            # answers_count = os.listdir(config.ANSWER_PATH)
            # if (answers_count.__len__() > 10):
            #     return
            get_patch_commits(same_file, folder)
            same_file.close()
            # 判断same_file 为空？

    # todo undertake different_patch.csv

    # todo the commit message of the retrieved commit is the same as, con-tains, or is contained by the commit message of the selected patch



def pre_build_pipeline(folders):
    for folder in folders:

        same_file = open(os.path.join(f'{config.TEST_PATH}{folder}/same_patch.csv'), "r", errors='ignore')
        build_pipeline(same_file, folder)
        # 判断same_file 为空？

def build_pipeline(file,folder):
    cve = folder
    cve_issue = {}
    cve_pr = {}
    candidate_commits = {}
    patch_commits = {}
    patch_hash = set()
    # 读取repo_config.csv文件
    if not os.path.exists(f'{config.TEST_PATH}{folder}/repo_config.csv'):
        print(f'{folder} repo_config.csv is None')
        return None
    repo_file = open(f'{config.TEST_PATH}{folder}/repo_config.csv', "r")
    reader = csv.reader(repo_file)
    first_row = next(reader)
    owner = first_row[0]
    repo = first_row[1]
    # file = open(f'/data/zy/pythonProject/CVEKnowledgeMap/output/CVE-2020-9548/same_patch.csv', "r")

    reader = csv.reader(file)

    # 遍历reader对象，获取每一行的长度
    rows = []
    # 如果csv模块的字段超过最大长度

    csv.field_size_limit(10000000)
    # 遍历reader对象，尝试读取每一行
    for row in reader:
        try:
            if row.__len__() > 2 and row[2].__len__() < 1000 and row.__len__() > 3 and row[3].__len__() < 1000:
                # 将每一行添加到rows列表中
                rows.append(row)
            # print(row)
        except UnicodeDecodeError:
            pass

    description = get_cve_description(cve)

    # if num > 50:
    #     mylogger.warning("commit数量>50的 cve编号是" + cve)
    #     continue

    # if not os.path.exists(config.PIPILINE_PATH + cve):
    for line in rows:
        # todo Assume : All Fix #123 is issue id //后续处理等效数据集修改
        # todo PR 的#id
        candidate_commits[candidate_commits.__len__()] = line

        if not os.path.exists(config.PIPILINE_PATH + cve):
            os.makedirs(config.PIPILINE_PATH + cve)
        # with open(f'{config.PIPILINE_PATH}{cve}/cve_issue.pkl', 'wb') as f:
        #     pickle.dump(cve_issue, f)
        # with open(f'{config.PIPILINE_PATH}{cve}/cve_pr.pkl', 'wb') as f:
        #     pickle.dump(cve_pr, f)
        # with open(f'{config.PIPILINE_PATH}{cve}/candidate_commits.pkl', 'wb') as f:
        #     pickle.dump(candidate_commits, f)
        # with open(f'{config.PIPILINE_PATH}{cve}/patch_commits.pkl', 'wb') as f:
        #     pickle.dump(patch_commits, f)

if __name__ == '__main__':
    # 指定目录
    # directory = config.TEST_PATH
    # folders = os.listdir(config.TEST_PATH)
    # for folder in folders.copy():
    #     if folder in os.listdir(config.PIPILINE_PATH):
    #         folders.remove(folder)


    c = read_cve_file('/data/zy/pythonProject/CVEKnowledgeMap/resource/FinaltestCve.txt')
    c = list(c)
    c = sorted(c)
    get_commits_files(c)

    # pre_build_pipeline(folders)
