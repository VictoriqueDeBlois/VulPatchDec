import csv
import json
import os
import logging
import pickle
import re

import requests
from bs4 import BeautifulSoup

import config
answer_dir = config.ANSWER_PATH
pipeline_dir = config.PIPILINE_PATH

def extract_product_version(cve):
    file = config.CVE_PATH+'ans_pro_ver/'  + cve+".txt"
    product = None
    version = None
    with open(file, "r") as f:
        text = f.read()
        for line in text.split("\n"):
        # Use regex to find PRODUCT and VERSION
            if 'PRODUCT:' in line:
                # Use regex to find PRODUCT and capture the content after 'PRODUCT:'
                match = re.search(r"PRODUCT:\s*(.*?)(?=\s*VERSION:|$)", line)
                if match:
                    product = match.group(1).strip()

            # Check if the line contains 'VERSION:'
            if 'VERSION:' in line:
                # Use regex to find VERSION and capture the content after 'VERSION:'
                match = re.search(r"VERSION:\s*(.*)", line)
                if match:

                    last_word = match.group(1).strip().split(" ")[-1]
                    # Check if the last word contains a number
                    if any(char.isdigit() for char in last_word):
                        version = last_word
                        break
                    else:
                        with open(f'version_not_found.csv', 'a') as file:
                            writer = csv.writer(file)
                            writer.writerow([cve])


    with open(f'{config.PRODU_VER}{cve}.csv', "w") as f:
        writer = csv.writer(f)
        writer.writerow([product, version])
    return  product, version

def longestCommonSubstr(word1: str, word2: str) -> int:
    m = len(word1)
    n = len(word2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    # dp[i][j]代表word1以i结尾,word2以j结尾，的最大公共子串的长度

    max_len = 0
    row = 0
    col = 0
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if word1[i - 1] == word2[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
                if max_len < dp[i][j]:
                    max_len = dp[i][j]
                    row = i
                    col = j

    max_str = ""
    i = row
    j = col
    while i > 0 and j > 0:
        if dp[i][j] == 0:
            break
        i -= 1
        j -= 1
        max_str += word1[i]

    lcstr = max_str[::-1]
    # 回溯的得到的最长公共子串
    # print(max_len)

    return max_len

def get_numbers_with_answer(text):
    words = text.split()
    numbers = []
    for word in words:
        try:
            number = int(word)
            numbers.append(number)
        except ValueError:
            pass
    return numbers

def get_numbers_with_hash(text,tag):
    # 使用空格来分割一段话
    words = text.split()
    # 创建一个空列表，用来存放 # 开头的数字
    numbers = []
    # 遍历每个单词
    for word in words:
        # 检查单词是否以 # 开头
        if tag == "#":
            if word.__contains__(tag):
                word = word.strip(tag)
                match = re.search(r"\d+", word)
                if match:
                    # 如果有匹配，取出匹配的部分
                    num = match.group()
                    numbers.append(num)
                    # numbers.append(word)
    # 返回列表
    return numbers

def get_pr_content(owrner,repo, id,cve):
    url = f'https://github.com/{owrner}/{repo}/pull/{id}'
    # 定义最大重试次数，例如3次
    max_retries = 1
    # 定义当前重试次数，初始为0
    current_retries = 0
    # 使用一个循环，来重试请求
    while current_retries < max_retries:
        try:
            # 使用requests库的get方法，发送请求，获取网页内容，指定超时时间为10秒
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                print("请求失败，状态码为", response.status_code)
                return response.status_code
            # 如果请求成功，跳出循环
            # 使用BeautifulSoup解析网页内容
            soup = BeautifulSoup(response.text, "html.parser")
            # 使用正则表达式搜索CVE-2020-9548的字符串
            parts = cve.split("-")
            # 设计正则表达式表示含有part[0]任意字符parts[1]任意字符parts[2]任意字符的字符串
            title = soup.title.string
            print(title)
            # 使用正则表达式搜索网页内容
            # 如果找到了，返回True，否则返回False
            return title
        except requests.exceptions.Timeout as e:
            # 如果请求超时，打印异常信息
            print(e)
            # 增加当前重试次数
            current_retries += 1
        except requests.exceptions.RequestException as e:
            # 如果发生其他请求异常，打印异常信息
            print(e)
            # 跳出循环
            break
            # 返回请求结果
        return cve
    # 检查状态码，如果不是200，表示请求失败
def get_issue_content(owrner,repo, id,cve):
    url = f'https://github.com/{owrner}/{repo}/issues/{id}'
    try:
        # 使用requests库的get方法，发送请求，获取网页内容，指定超时时间为10秒
        response = requests.get(url, timeout=10)
        if response.status_code == 404:
            return 404
        # 如果请求成功，跳出循环
        # 使用BeautifulSoup解析网页内容
        soup = BeautifulSoup(response.text, "html.parser")

        # 获取<title>标签中的内容
        title = soup.title.string.strip()  # 去除两端的空白字符

        print(title)        #获取title内的内容
        return title

    # except requests.exceptions.Timeout as e:
    #     # 如果请求超时，打印异常信息
    #     print(e)
    #     # 增加当前重试次数
    #     current_retries += 1
    except requests.exceptions.RequestException as e:
        # 如果发生其他请求异常，打印异常信息
        # 跳出循环
        # 返回请求结果
        return cve
    # 检查状态码，如果不是200，表示请求失败
#得到答案文件中频度最高的patch number
def get_most_common_patch_number(frequency_dict,cve):
    answer_prompts = []
    if frequency_dict == {}:
        with open(f'{pipeline_dir}freIsEmpty.csv', 'w') as file:
            writer = csv.writer(file)
            writer.writerow([cve])
        return answer_prompts,0,0
    max_frequency = max(frequency_dict.values())
    most_common_values = [key for key, value in frequency_dict.items() if value == max_frequency]
    # print(frequency_dict)
    for patch_number in most_common_values:
        if not patch_number.isdigit():
            continue
        answer_prompts.append(read_candidate_commits(cve, patch_number))
    return answer_prompts,max_frequency,most_common_values


def get_patch_number_By_Freq(frequency_dict,cve,fre):
    answer_prompts = []
    if frequency_dict == {}:
        with open(f'{pipeline_dir}freIsEmpty.csv', 'w') as file:
            writer = csv.writer(file)
            writer.writerow([cve])
        return answer_prompts,0,0
    keys = list(frequency_dict.keys())
    res = []
    answer_prompts = []
    for key,value in frequency_dict.items():
        if value >fre:
            if not key.isdigit():
                continue
            answer_prompt = read_candidate_commits(cve, key)
            res.append([key,value,answer_prompt])
            answer_prompts.append(answer_prompt)
    return res,answer_prompts


# Function to read the candidate commits
def read_candidate_commits(folder, patch_number):
    pkl_file = os.path.join(pipeline_dir, folder, 'candidate_commits.pkl')
    with open(pkl_file, 'rb') as file:
        candidate_commits = pickle.load(file)
        return candidate_commits.get(int(patch_number))

def extract_commitID(folder_path,file_name,cve):
    file_path = os.path.join(folder_path, file_name)
    patch_frequency = {}
    with open(file_path, 'r') as file:
        lines = file.readlines()
        read_lines = False
        linecount = 0
        for line in lines:
            linecount += 1
            # Check if the line contains the folder name
            if line.startswith(cve):
                read_lines = True
                break
            # If reading lines, check for the Patch Number
        for line in lines:
            if linecount == 0 or not read_lines:
                read_lines = False
                if line.__contains__('Patch Number:') and re.search('Patch Number', line):
                    # 获得该行的数字
                    if re.search(r'Patch Number: \d+', line) is None:
                        continue
                    patch_number = (re.search(r'Patch Number: \d+', line).group()).split(": ")[1].strip()
                    if not patch_number.isdigit():
                        continue
                    # 如果找到了，增加出现次数
                    patch_frequency[patch_number] = patch_frequency.get(patch_number, 0) + 1
            linecount -= 1
    return patch_frequency

def get_cve_list(path):
    with open(path, "r") as f:
        data1 = json.load(f)
        f.close()
    # 获取字典键并存储在一个列表中
    keys1 = list(data1.keys())
    tracer_find_pathc_cve = identify_null_file(config.TRACER_COMMIT_PATH)
    keys = list(set(keys1) | (set(tracer_find_pathc_cve)))

    return keys


def identify_null_file(file_path):
    commits = os.listdir(file_path)
    res = []
    for file in commits:
        # 判断文件内容是否为空
        if os.path.getsize(file_path + file) != 0:
            res.append(file)
            # print(file)

    return res


if __name__ == '__main__':
    patch_frequency =  extract_commitID(f'/data/zy/pythonProject/CVEKnowledgeMap/answer/CVE-2017-7666/round1',f'answer550.txt',"CVE-2017-7666")
    get_most_common_patch_number(patch_frequency,"CVE-2017-7666")