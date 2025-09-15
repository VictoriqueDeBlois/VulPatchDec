# 导入所需的模块
import requests
import json
import pandas as pd

# 定义一个函数，根据给定的URL获取JSON数据
def get_json(url):
    response = requests.get(url)
    return response.json()

# 定义一个函数，根据给定的JSON数据解析出CVE ID和描述列表
def parse_json(data):
    # 获取CVE记录列表
    cve_list = data["vulnerabilities"]
    # 创建一个空列表，用于存储CVE ID和描述
    data = []
    # 遍历每个CVE记录，获取CVE ID和描述
    for cve in cve_list:
        cve_id = cve["cve"]["id"]
        print(cve_id)
        descriptions = cve["cve"]["descriptions"]
        for description in descriptions:
            if description["lang"] == "en":
                description = description["value"]
                # 将CVE ID和描述添加到列表中
                data.append([cve_id, description])
                # print(description)


    # 返回列表
    return data

# 定义一个函数，根据给定的数据创建一个CSV文件
def create_csv(data, filename):
    # 创建一个数据框，指定列名为CVE ID和Description
    df = pd.DataFrame(data, columns=["CVE ID", "Description"])
    # 将数据框写入CSV文件，指定编码为UTF-8，不写入索引
    df.to_csv(filename, encoding="utf-8", index=False)

# 定义一个主函数，用于执行爬虫程序

def getCVE(startIndex):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex="+str(startIndex)+"&resultsPerPage=2000"
    # 获取JSON数据
    data = get_json(url)
    # 解析JSON数据，得到CVE ID和描述的列表
    cve_data = parse_json(data)
    # 创建一个CSV文件，保存数据
    create_csv(cve_data, "cve_data_"+str(startIndex)+".csv")
def main():
    for i in range(0, 250000, 2000):
        getCVE(i)



# 调用主函数
if __name__ == "__main__":
    main()
