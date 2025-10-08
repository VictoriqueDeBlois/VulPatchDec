#得到深TEST目录下的所有文件夹
import csv
import os

import config
from util.vera_util import get_vera_found


#
# with open ("../resource/depth_dataset.csv", 'r') as f:
#     reader = csv.reader(f)
#     # 跳过第一行
#     next(reader)
#
#     for row in reader:
#         key = row[0]
#         value = row[3]
#
#         if not 'CVE-' in key or value  == '':
#             continue
#         if key in map:
#             map[key].append(value)
#         else:
#             map[key] = [value]
def datasetAnalysis():
    with open('../dataset.txt', 'r') as f:
        data = f.readlines()
        data = [x.strip() for x in data]
        keys = list(data)
    #读取CVE-后的数字，存储在keys中，并得到每个年份的CVE数量
    keys = []
    year_map = {}
    #按照从小到达
    for key in data:
        keys.append(key.split('-')[1])
        year = key.split('-')[1]
        if year in year_map:
            year_map[year] += 1
        else:
            year_map[year] = 1
    #得到每个年份的CVE数量
    for key in year_map:
        print(key, year_map[key])
def veraAnalysisi():
    vera = os.listdir('../VulnerCollector/vera/result')
def get_new_data():
    vera = os.listdir('../VulnerCollector/vera/result')
    snyk = os.listdir('../VulnerCollector/snyk/search_page')
    data = {}
    with open('../vera.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            cve = row[0]
            version = row[1]
            commit = row[2]
            if cve+'.html' in snyk:
                if cve in data:
                    if version in data[cve]:
                        data[cve][version].add(commit)
                    else:
                        data[cve][version] = set()
                        data[cve][version].add(commit)
                else:
                    data[cve] = {}
                    data[cve][version] = set()
                    data[cve][version].add(commit)




    # data = {}
    # for url in vera:
    #     cve = url.split('.')[0]
    #     year = cve.split('-')[1]
    #     #判断是否是2020年及之后的CVE
    #     if int(year)<2020:
    #         continue
    #
    #     value = get_vera_found('../VulnerCollector/vera/result/'+url)
    #     if value.__len__()!=0:
    #         data[cve] = value
    # with open('../vera.csv', 'w') as f:
    #     writer = csv.writer(f)
    #     for key in data:
    #         for patch in data[key]:
    #             verison = patch
    #             commits = data[key][patch]
    #             for commit in commits:
    #                 writer.writerow([key,verison,commit])
def get_new_cves():
    data = {}
    with open ('../resource/vera.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            cve = row[0]
            version = row[1]
            commit = row[2]
            if cve in data:
                if version in data[cve]:
                    data[cve][version].add(commit)
                else:
                    data[cve][version] = set()
                    data[cve][version].add(commit)
            else:
                data[cve] = {}
                data[cve][version] = set()
                data[cve][version].add(commit)
    print(data.__len__())

    with open('../resource/new_dataset.txt','w') as f:
        for cve in list(data.keys())[:817]:
            f.write(cve+'\n')
def get_6_lan_cve():
    with open('../resource/depth_dataset.csv', 'r') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if row[1] == 'C':
                print(row[0])
from github import Github

# 使用个人访问令牌进行身份验证
g = Github("your_personal_access_token")

# 克隆的项目的仓库名 (例如：'owner/repository')
repo_name = 'owner/repository'
repo = g.get_repo(repo_name)

# 获取项目的语言信息
languages = repo.get_languages()

# 打印每种语言的使用行数
for language, lines in languages.items():
    print(f"{language}: {lines} lines")

if __name__ == '__main__':
    # get_new_data()
    get_new_cves()

