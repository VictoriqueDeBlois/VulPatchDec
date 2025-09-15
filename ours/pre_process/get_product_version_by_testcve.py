import csv
import os
from itertools import product

import requests

import config
from util.ask_GPT import ask_gpt_turbo
from util.cve_parser import get_cve_description




def get_version_by_gpt(cveid):
    description = get_cve_description(cveid)
    promot = (
            "Descriptions often follow this template: "
            "[PROBLEM TYPE] in [PRODUCT/VERSION] causes [IMPACT] when [ATTACK]\n"
            "Please help me extract the PRODUCT and VERSION.\n\n"
            "For Example:\n"
            "Q: CVEID: CVE-2025-1010. Description: A buffer overflow in the XYZ software before version 1.2.3 causes a denial of service "
            "when an attacker sends a specially crafted packet.\n"
            "A: \n"
            "XYZ\n"
            "1.2.3\n"
            "Q is: " + cveid + ".Description: " + description + "Please give me an answer without anything else."

    )
    print(promot)

    # 使用GPT-3.5-turbo模型获取产品和版本信息
    ans = ask_gpt_turbo(description)
    print(ans)
    os.mkdir(f'{config.PRODU_VER}{cveid}')
    with open(f'{config.PRODU_VER}{cveid}/answer.txt', "w") as f:
        f.write(ans)
    product = None
    version = None
    for line in ans:
        if "Product" in line:
            product = line.split(":")[1].strip()
        if "FixedVersion" in line:
            version = line.split(":")[1].strip()


    # 将产品和版本信息写入CSV文件
    with open(f'{config.PRODU_VER}{cveid}.csv', "w") as f:
        writer = csv.writer(f)
        writer.writerow([product, version])


def get_product_plus_version(cveid):
    # 发送HTTP请求获取JSON数据
    url = f'https://cveawg.mitre.org/api/cve/{cveid}'
    response = requests.get(url)
    json_data = response.json()

    # 提取"containers"中的"product"和"version"信息
    containers = json_data.get("containers", {})
    for cna, details in containers.items():
        affected = details.get("affected", [])
        for item in affected:
            product = item.get("product")
            versions = item.get("versions", [])
            for version_info in versions:
                version = version_info.get("version")
                with open(f'{config.PRODU_VER}{cveid}.csv', "w") as f:
                    writer = csv.writer(f)
                    if product == 'n/a' or version == 'n/a':
                        print(f'{cveid} has no product or version info')
                        continue
                    writer.writerow([product, version])


if __name__ == '__main__':
    data1 = set()
    with open('../resource/depth_dataset.csv', "r") as f:
        reader = csv.reader(f)
        for row in reader:
            data1.add(row[0])
    # 获取字典键并存储在一个列表中
    keys1 = list(data1)
    for cve in keys1:
        get_product_plus_version(cve)
    # get_version_by_gpt('CVE-2019-10754')
