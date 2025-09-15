# 定义一个函数，用于根据CVE编号获取/data/zy/pythonProject/cve/cve_lcs目录下同名 cveid.csv文件，如果没有则输出"closed “，有则获取第一列数据，并返回即可
import json
import re

import config


def get_product_by_cpe(cpe, flag):
    # 按照冒号（:）分割 CPE 字符串，得到一个列表
    parts = cpe.split(":")
    # 如果列表的长度大于等于 4（表示有产品名称部分）
    if len(parts) >= 5:
        # 返回列表的第四个元素（索引为 3）
        if flag and parts[2] == "a":
            s = parts[4].lower()
            result = re.sub('[\W_]+', '', s)
            return result
        s = parts[4].lower()
        result = re.sub('[\W_]+', '', s)
        return result
    # 否则
    else:
        # 返回 None
        return None
def get_cpe_by_cve(item):
    # 创建一个空列表，用于存储cpe信息
    cpe_list = set()
    # 获取CVE项中的配置信息，返回一个列表
    configs = item["configurations"]["nodes"]
    # 遍历配置信息中的每个节点
    for node in configs:
        # 如果节点有cpe_match属性，说明是一个cpe匹配节点
        if node["cpe_match"].__len__() != 0:
            # 遍历节点中的每个cpe匹配对象
            for cpe in node['cpe_match']:
                # 如果cpe对象有cpe23Uri属性，说明是一个cpe 2.3版本的标识符
                if cpe.get('vulnerable') == True and cpe.get('cpe23Uri'):
                    # 将cpe 2.3版本的标识符添加到cpe列表中
                    if configs.__len__() > 10:
                        cpe_product = get_product_by_cpe(cpe['cpe23Uri'], True)
                    else:
                        cpe_product = get_product_by_cpe(cpe['cpe23Uri'], False)
                    if cpe_product is not None:
                        cpe_list.add(cpe_product)
        elif node["children"].__len__() != 0:
            for child in node['children']:
                # 如果cpe对象有cpe23Uri属性，说明是一个cpe 2.3版本的标识符
                for cpe in child["cpe_match"]:
                    # 如果cpe对象有cpe23Uri属性，说明是一个cpe 2.3版本的标识符
                    if cpe.get('vulnerable') == True and cpe.get('cpe23Uri'):
                        # 将cpe 2.3版本的标识符添加到cpe列表中
                        if node['children'].__len__() > 10:
                            cpe_product = get_product_by_cpe(cpe['cpe23Uri'], True)
                        else:
                            cpe_product = get_product_by_cpe(cpe['cpe23Uri'], False)
                        if cpe_product is not None:
                            cpe_list.add(cpe_product)
    # 返回cpe列表
    return cpe_list
def get_cve_list():
    # 定义一个空列表，用于存储读取的数据
    # 导入json模块

    # 打开文件并读取内容
    with open(config.DBA_CVEID_PATH, "r") as f:
        data1 = json.load(f)

    # 获取字典键并存储在一个列表中
    keys1 = list(data1.keys())

    with open(config.DBB_CVEID_PATH, "r") as f:
        data2 = json.load(f)

    # 获取字典键并存储在一个列表中
    keys2 = list(data2.keys())

    # 交集
    # keys = list(set(keys1) & (set(keys2)))

    # 获取两个列表的交集
    keys = list(set(keys1) | (set(keys2)))
    print(keys.__len__())
    # existcommits = os.listdir("/root/VulnerCollector/VulnerCollector/vdb_output/commit")
    # for exist in existcommits:
    #     for key in keys:
    #         if exist.replace(".txt", "") == key:
    #             keys.remove(key)
    # print(keys.__len__())

    return keys

def get_cve_description(cve):
    # 遍历文件名，打开每个文件

    description = None
    cpe_list = set()

    year = cve.split("-")[1]
    cve_file = open(f'{config.CVE_DATA_PATH}nvdcve-1.1-{year}.json', "r")
    data = json.load(cve_file)
    for item in data["CVE_Items"]:
        # 获取CVE项中的cveid
        # 跳过之前
        cveid = item["cve"]["CVE_data_meta"]["ID"]
        if cveid != cve:
            continue
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
        # print(cveid)
        # 获取CVE项中的cvedescription
        description = item["cve"]["description"]["description_data"][0]["value"]
    return description
def get_cve_description_cpe(cve):
    # 遍历文件名，打开每个文件

    description = None
    cpe_list = set()

    year = cve.split("-")[1]
    cve_file = open(f'{config.CVE_DATA_PATH}nvdcve-1.1-{year}.json', "r")
    data = json.load(cve_file)
    for item in data["CVE_Items"]:
        # 获取CVE项中的cveid
        # 跳过之前
        cveid = item["cve"]["CVE_data_meta"]["ID"]
        if cveid != cve:
            continue
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
        # 创建一个空列表，用于存储cpe信息
        # 获取CVE项中的配置信息，返回一个列表
        configs = item["configurations"]["nodes"]
        # 遍历配置信息中的每个节点
        for node in configs:
            # 如果节点有cpe_match属性，说明是一个cpe匹配节点
            if node["cpe_match"].__len__() != 0:
                # 遍历节点中的每个cpe匹配对象
                for cpe in node['cpe_match']:
                    # 如果cpe对象有cpe23Uri属性，说明是一个cpe 2.3版本的标识符
                    if cpe.get('vulnerable') == True and cpe.get('cpe23Uri'):
                        # 将cpe 2.3版本的标识符添加到cpe列表中
                        if configs.__len__() > 10:
                            cpe_product = get_product_by_cpe(cpe['cpe23Uri'], True)
                        else:
                            cpe_product = get_product_by_cpe(cpe['cpe23Uri'], False)
                        if cpe_product is not None:
                            cpe_list.add(cpe_product)
            elif node["children"].__len__() != 0:
                for child in node['children']:
                    # 如果cpe对象有cpe23Uri属性，说明是一个cpe 2.3版本的标识符
                    for cpe in child["cpe_match"]:
                        # 如果cpe对象有cpe23Uri属性，说明是一个cpe 2.3版本的标识符
                        if cpe.get('vulnerable') == True and cpe.get('cpe23Uri'):
                            # 将cpe 2.3版本的标识符添加到cpe列表中
                            if node['children'].__len__() > 10:
                                cpe_product = get_product_by_cpe(cpe['cpe23Uri'], True)
                            else:
                                cpe_product = get_product_by_cpe(cpe['cpe23Uri'], False)
                            if cpe_product is not None:
                                cpe_list.add(cpe_product)
        break
    return description,cpe_list