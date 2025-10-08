import csv
import json
import logging
import os
import re
import threading

import spacy
from tqdm import tqdm

import config
from pre_process.github_lang import get_repo_main_language
from util.tool import longestCommonSubstr
from util.cve_parser import get_cve_list, get_cve_description_cpe, get_cpe_by_cve

lang_dir = "../pythonProject/data/"
cve_dir = "../VulnerCollector/data/CVE/DataSet-NVD"


# 定义一个函数，用于判断一个词是否是代词
def is_pronoun(token):
    # 如果词的词性是 PRON（代词），或者词的形态特征中有 PronType（代词类型）
    if token.pos_ == "PRON" or "PronType" in token.morph:
        # 返回 True
        return True
    # 否则
    else:
        # 返回 False
        return False


def get_non(text):
    nlp = spacy.load("en_core_web_sm")
    doc = nlp(text)
    result = []
    for np in doc.noun_chunks:
        if not is_pronoun(np.root):
            # 把名词短语的根词加入到列表中
            result.append(np.root.text)
            print(np.root.text)
    return result


# 定义一个函数，用于根据CVE的description筛选闭源软件
# 定义一个函数，用于判断cve描述中是否存在闭源软件
def filter_closed_source_software(cveid, cve_description):
    # 定义一个闭源软件的列表，您可以根据需要添加或删除其中的元素
    closed_source_software = ["Windows", "MacOS", "iOS", "Adobe", "Oracle", "Microsoft Office", "Photoshop", "Skype",
                              "Zoom", "WeChat"]
    # 遍历闭源软件的列表
    for software in closed_source_software:
        # 判断cve描述中是否包含闭源软件的名称，忽略大小写
        if f' {software.lower()} ' in cve_description:
            with open("closed_source_software.csv", "a+", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([cveid, cve_description, software])
                f.close()
            # 如果包含，则返回True
            return True
    # 如果不包含，则返回False
    return False


main_language = ["C++", "C", "Java", "Python", "JavaScript", "Go"]

# tag = 0
# lock = threading.Lock()

token = "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"
dict = {}


def get_main_language_project(cveid):
    #读取repo_config.csv
    if not os.path.exists(f'{config.TEST_PATH}{cveid}/repo_config.csv'):
        print(f'{cveid} repo_config.csv is None')
        return None
    repo_file = open(f'{config.TEST_PATH}{cveid}/repo_config.csv', "r")
    reader = csv.reader(repo_file)
    try:
        first_row = next(reader)  # 读取第一行
    except StopIteration:
        print(f'{cve} same_patch 是空的，跳过处理')
        return None # 如果文件为空，返回或跳过处理
    owner = first_row[0]
    repo = first_row[1]
    result = get_repo_main_language(owner, repo, token=token)
    if 'main_language' in result and result['main_language']:
        lang = result['main_language']
    else:
        print(f"{owner}/{repo}: {result.get('message', result.get('error', '未知错误'))}")
        return None
    with open(f'{config.RESOURCE_PATH}language_cve_all.csv', 'a+') as f:
        writer = csv.writer(f)
        writer.writerow([cveid, owner, repo, lang])
    # main_lan = ["Java","C++","Python","JavaScript","Go","C"]
    # for lang in main_lan:
    #     open_file = open(lang_dir + lang+'.csv', "r")
    #     reader = csv.reader(open_file)
    #     rows = list(reader)
    #     for line in rows:
    #         if f'{owner}/{repo}' in line[1]:
    #             with open(f'{config.RESOURCE_PATH}language_cve.csv', 'a+') as f:
    #                 writer = csv.writer(f)
    #                 writer.writerow([cveid, owner, repo, lang])
    #                 f.close()
    #             break
    #     open_file.close()
    return None

def screen(cveid, cpe_products, cpe_tag):
    res = set()
    for cpe in cpe_products:
        # 已经处理过该软件
        if cpe in dict:
            for i in dict[cpe]:
                res.add(i)
            continue
        print(cpe)
        similarity_list = []

        # tag = False
        # for lang in os.listdir(lang_dir):
        #     lang = lang.replace(".csv", "")
        #     if f'.{lang.lower()}' in des_low:
        #         tag = True
        #         find_lan = lang
        #         break
        #     elif f'.cpp' in des_low:
        #         tag = True
        #         find_lan = "C++"
        #         break
        #     elif f'.js' in des_low:
        #         tag = True
        #         find_lan = "JavaScript"
        #         break
        #     elif f' {lang.lower()} ' in des_low:
        #         # 描述中存在多个语言
        #         if tag == True:
        #             tag = False
        #             break
        #         tag = True
        #         find_lan = lang
        #         test("lang:" + lang)

        # if tag == False:
        # 处理所有语言仓库
        for lang in os.listdir(lang_dir):

            open_file = open(lang_dir + lang, "r")
            reader = csv.reader(open_file)
            next(reader)
            for line in reader:
                s = line[0].lower()
                name = re.sub('[\W_]+', '', s)
                link = line[1]

                if len(name) > 2 and f'{name}' == cpe and cpe_tag == True:
                    res.add((name, 50, 50, lang.replace(".csv",""), link, cpe))
                    break
                else:
                    similarity = longestCommonSubstr(name, cpe)
                    # if similarity > 2 and similarity / len(name) > 0.5:
                    if similarity > 2:
                        similarity_list.append((s, similarity, similarity / len(name), lang.replace(".csv",""), cpe, link))

                # res_sim.append(name,similarity)
                # 关闭文件
            open_file.close()
            # 对列表按照相似度降序排序

            similarity_list.sort(key=lambda x: (x[1], x[2]), reverse=True)
            # 得到十个相似度最高的元组，存入cveid.csv文件中

            del similarity_list[10:]

        # else:
        #     open_file = open(lang_dir + find_lan + ".csv", "r")
        #     reader = csv.reader(open_file)
        #
        #     next(reader)
        #     for line in reader:
        #         s = line[0].lower()
        #         name = re.sub('[\W_]+', '', s)
        #         link = line[1]
        #         if f'{name}' == cpe:
        #             res.add((name, 100, find_lan, link, cpe))
        #             break
        #         else:
        #             similarity = longestCommonSubstr(name, cpe)
        #
        #             if similarity > 2:
        #                 similarity_list.append((s, similarity, find_lan, link, cpe))
        #
        #         # res_sim.append(name,similarity)
        #         # 关闭文件
        #     open_file.close()
        #     similarity_list.sort(key=lambda x: x[1], reverse=True)
        #     del similarity_list[10:]

        # 每个cpe找到10个相似度最高的放入res
        for i in similarity_list:
            res.add(i)
        dict[cpe] = similarity_list

    if res.__len__() != 0:
        output_file = open("./cve/4602_related_repos/" + cveid + ".csv", "w")
        output_writer = csv.writer(output_file)
        output_writer.writerow(["name", "similarity", "similarity/name.length" "lang", "cpe", "link"])
        for i in res:
            res.add(i)
        for line in res:
            output_writer.writerow(line)
        output_file.close()


count = 1


def read_file(file_name):
    global count
    data = get_data(file_name)
    # 对于每一行调用screen函数
    for item in data["CVE_Items"]:
        # 获取CVE项中的cveid
        # 跳过之前
        cveid = item["cve"]["CVE_data_meta"]["ID"]
        # 跳过之前
        # if count <=35524:
        #     count = count + 1
        #     continue

        # for exisit in os.listdir("./cve/cve_related_repos"):
        #     if exisit == cveid+".csv":
        #         count = count+1
        #         print(exisit)
        #         tag = True
        #         break
        # if tag:
        #     continue
        print(cveid)
        # 获取CVE项中的cvedescription
        description = item["cve"]["description"]["description_data"][0]["value"]
        # 获取CVE项中的cpe信息，返回一个列表s
        des_low = description.lower()
        if filter_closed_source_software(cveid, des_low) == True:
            print("closed source software : " + str(cveid))
        else:
            cpe_list = get_cpe_by_cve(item)
            if cpe_list.__len__() != 0:

                screen(cveid, cpe_list, True)
            else:
                with open("no_cpe.csv", "a+", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([cveid, des_low])
                    f.close()
                screen(cveid, get_non(des_low), False)

    # 关闭文件


# 定义一个函数，根据json文件的路径获取Python对象
def get_data(json_file):
    # 打开json文件，以只读模式
    with open(json_file, "r") as f:
        # 读取json文件的内容
        json_data = f.read()
        # 将json文件的内容转换为Python对象
        data = json.loads(json_data)
        # 返回Python对象
        return data


# CVE-2017-8109
if __name__ == '__main__':
    os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7890'
    os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7890'
    # keys = get_cve_list()
    # # keys = ["CVE-2017-8109"]
    # for cve in keys:
    #
    #     # cve = "CVE-2020-9548"
    #     if cve + ".csv" in os.listdir("./cve/4602_related_repos"):
    #         continue
    #     description, cpe_list = get_cve_description_cpe(cve)
    #     if description is None:
    #         continue
    #     des_low = description.lower()
    #
    #     # cpe_list = get_cpe_by_cve(item)
    #     if cpe_list.__len__() != 0:
    #         screen(cve, des_low, cpe_list, True)
    #     else:
    #         with open("4602_no_cpe.csv", "a+", encoding="utf-8") as f:
    #             writer = csv.writer(f)
    #             writer.writerow([cve, des_low])
    #             f.close()
    #         screen(cve, des_low, get_non(des_low), False)
    with open(f'{config.RESOURCE_PATH}FinaltestCve.txt', 'r') as f:
        test = f.readlines()
        test = [x.strip() for x in test]
    # cves = []
    # with open(f'{config.RESOURCE_PATH}main_language_cve.csv', 'r') as f:
    #     reader = csv.reader(f)
    #     for row in reader:
    #         cves.append(row[0])
    # test = list(set(test) - set(cves))
    for cve in tqdm(test):
        get_main_language_project(cve)
        # read_file(config.TEST_PATH + cve)
        # break
# # 定义一个常量，表示文件所在的目录
# FILE_DIR = cve_dir
# # 遍历目录中的所有文件
# # 获取cve目录下的所有文件名
# if not os.path.exists("./cve/cve_related_repos"):
#     # 如果不存在，则新建目录
#     os.mkdir("./cve/cve_related_repos")
# # else :
# #     for file_name in os.listdir("./cve/cve_related_repos"):
# #         os.remove("./cve/cve_related_repos/"+file_name)
# for file in os.listdir(FILE_DIR):
#     if file.endswith(".json"):
#         # 构造文件的完整路径，并添加到队列中
#         file_path = os.path.join(FILE_DIR, file)
#         print(file_path)
#         read_file(file_path)

    print(" All finished")
