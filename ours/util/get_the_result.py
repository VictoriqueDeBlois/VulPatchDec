import csv
import glob
import os
import pickle
import re

import config
from util.tool import extract_commitID, get_most_common_patch_number, read_candidate_commits, get_patch_number_By_Freq

# Define the base directories
answer_dir = config.ANSWER_PATH
print(answer_dir)
pipeline_dir = config.PIPILINE_PATH


# 读取answer文件并得到频度第一的提交

def read_the_answer_by_index_accuracy(cves,index,round,map):
    count = 0
    len = 0
    correct_count = 0
    recall = 0
    for folder in cves:
        #得到answer文件夹下的所有answer文件
        folder_path = os.path.join(answer_dir, folder)
        # folder_path = "/data/zy/pythonProject/CVEKnowledgeMap/answer/CVE-2017-7666"
        cve = folder
        if os.path.isdir(folder_path):
            # Iterate over each file in the folder
            files = glob.glob(f'{folder_path}/answer*')
            for i in range(index+1,round+1):
                if f'{folder_path}/answer{i}.txt'  in files:
                    files.remove(f'{folder_path}/answer{i}.txt')
            frequency_dict = {}
            for file_name in files:
                patch_frequency = extract_commitID(folder_path, file_name, folder)
                for key in patch_frequency:
                    frequency_dict[key] = frequency_dict.get(key, 0) + patch_frequency[key]

            # Get the most common patch number and save the answer prompts
            answer_prompts,max_frequency,most_common_values =  get_most_common_patch_number(frequency_dict,folder)
            len += 1
            if answer_prompts.__len__() == 0:
                continue
            #读取深度数据集
            dict = []
            if not cve in map:
                continue
            for link in map[cve]:
                m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', link)
                if m == None:
                    continue
                owner = m.group(1)
                repo = m.group(2)
                hash = m.group(3)
                dict.append([hash])
            flag = False
            correct = 0
            for commit in answer_prompts:
                if commit is None:
                    continue
                for i in dict:
                    try:
                        if i[0] in commit[0] or commit[0] in i[0] or i[0] in commit[1] or commit[1] in i[0] or commit[2] == i[1]:
                            flag = True
                            # correct+=1
                            correct+=1
                            break

                    except:
                        continue
            if flag:
                correct_count += 1
            count = count + correct / answer_prompts.__len__()
            recall = recall + correct /dict.__len__()
    print(len)
    print(correct_count)
    print(count / len)

def read_the_answer_by_index_recall(cves,index,round,map):
    count = 0
    len = 0
    correct_count = 0
    recall = 0
    for folder in cves:
        #得到answer文件夹下的所有answer文件
        folder_path = os.path.join(answer_dir, folder)
        # folder_path = "/data/zy/pythonProject/CVEKnowledgeMap/answer/CVE-2017-7666"
        cve = folder
        if os.path.isdir(folder_path):
            # Iterate over each file in the folder
            files = glob.glob(f'{folder_path}/answer*')
            for i in range(index+1,round+1):
                if f'{folder_path}/answer{i}.txt'  in files:
                    files.remove(f'{folder_path}/answer{i}.txt')
            frequency_dict = {}
            for file_name in files:
                patch_frequency = extract_commitID(folder_path, file_name, folder)
                for key in patch_frequency:
                    frequency_dict[key] = frequency_dict.get(key, 0) + patch_frequency[key]

            # Get the most common patch number and save the answer prompts
            answer_prompts,max_frequency,most_common_values =  get_most_common_patch_number(frequency_dict,folder)
            len += 1
            if answer_prompts.__len__() == 0:
                continue
            #读取深度数据集
            dict = []
            if not cve in map:
                continue
            for link in map[cve]:
                m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', link)
                if m == None:
                    continue
                owner = m.group(1)
                repo = m.group(2)
                hash = m.group(3)
                dict.append([hash])
            flag = False
            correct = 0
            for commit in answer_prompts:
                if commit is None:
                    continue
                for i in dict:
                    try:
                        if i[0] in commit[0] or commit[0] in i[0] or i[0] in commit[1] or commit[1] in i[0] or commit[2] == i[1]:
                            flag = True
                            correct+=1

                    except:
                        continue
            if flag:
                correct_count += 1
            count = count + correct / answer_prompts.__len__()
            recall = recall + correct /dict.__len__()
    print(recall / len)




def read_the_answer(folder):
# Iterate over each folder in the answer directory
    print(folder)
    folder_path = os.path.join(answer_dir, folder)
    # folder_path = "/data/zy/pythonProject/CVEKnowledgeMap/answer/CVE-2017-7666"
    cve = folder
    if os.path.isdir(folder_path):
        # Iterate over each file in the folder
        files = glob.glob(f'{folder_path}/answer*')
        frequency_dict = {}
        for file_name in files:
            patch_frequency = extract_commitID(folder_path, file_name, folder)
            for key in patch_frequency:
                frequency_dict[key] = frequency_dict.get(key, 0) + patch_frequency[key]

        # Get the most common patch number and save the answer prompts
        for fre in [0,5,7]:
            if frequency_dict == {}:
                break
            fre_res,answer_prompts = get_patch_number_By_Freq(frequency_dict,cve,fre)
            with open(f'{pipeline_dir}/{cve}/frequecy_by_fre_{fre}.csv', 'w') as file:
                writer = csv.writer(file)
                for row in fre_res:
                    writer.writerow(row)
                    print(row)
            with open(f'{pipeline_dir}/{cve}/answer_prompt_by_fre_{fre}.pkl', 'wb') as file:
                pickle.dump(answer_prompts, file)




        # answer_prompts,max_frequency,most_common_values =  get_most_common_patch_number(frequency_dict,folder)
        # # if max_frequency <5:
        # #     with open(f'frequency_below_5.txt', 'a+') as file:
        # #         file.write(f'{cve}\n')
        # # Save the answer prompts
        # with open(f'{pipeline_dir}/{cve}/answer_prompt.pkl', 'wb') as file:
        #     pickle.dump(answer_prompts, file)
        # with open(f'{pipeline_dir}/{cve}/frequecy.csv', 'w') as file:
        #     writer = csv.writer(file)
        #     writer.writerow([cve, most_common_values, max_frequency, answer_prompts])
        # print(f'Folder: {cve}, Most common values: {most_common_values}, Highest Frequency: {max_frequency},Hashes: {answer_prompts}')


if __name__ == '__main__':
    # not_in_vera = pickle.load(open(f'match_cve.pkl', "rb"))
    # for cve in not_in_vera:
    #     cves.remove(cve)
    # for cve in cves:
    #     read_the_answer(cve)]
    res = 0