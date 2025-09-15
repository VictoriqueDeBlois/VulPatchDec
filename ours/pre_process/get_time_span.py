import csv
import json
import os
import pickle
import re
from datetime import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup

import config
from util.github_util import get_commit_date

months = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9,
          "Oct": 10,
          "Nov": 11, "Dec": 12}


def get_redhat_create_time(url):
    # 发送get请求，获取网页内容
    print("redhat url")
    response = requests.get(url)
    # 判断请求是否成功
    if response.status_code == 200:
        # 导入BeautifulSoup库，用于解析网页内容
        # 创建一个BeautifulSoup对象，指定解析器为html.parser
        soup = BeautifulSoup(response.text, "html.parser")
        # 查找所有的td标签
        tds = soup.find_all("td")
        # 定义一个空列表，用于存储匹配的td
        matched_tds = []
        # 定义一个正则表达式，用于匹配XXXX-XX-XX格式的字符串
        regex = r"\d{4}-\d{2}-\d{2}"
        # 遍历所有的td标签
        for td in tds:
            # 获取td标签中的文本内容，去掉空白字符
            text = td.get_text().strip()
            # 判断文本内容是否符合正则表达式
            if re.search(regex, text):
                if "Reported:" in text:
                    matched_tds = re.search(regex, text).group()
                # 如果符合，将td标签添加到列表中
        # 打印匹配的td的个数
        return matched_tds

    else:
        return None


def get_commit_created_at(commit_url):
    # 从commit的url中提取仓库的owner，name和sha
    owner, name, sha = commit_url.split("/")[-4:-1]
    # 定义GitHub的API地址，传入owner，name和sha
    # api_url = f"https://api.github.com/repos/{owner}/{name}/commits/{sha}"
    api_url = commit_url.replace("github.com", "api.github.com/repos").replace("/commit/", "/commits/")
    headers = {
        "Authorization": "bearer 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",
        "Content-Type": "application/json"
    }
    if commit_url.find("/pull/") != -1:
        pattern = r"/pull/\d+/"
        api_url = re.sub(pattern, "/", api_url)
    # 发送GET请求，获取commit的信息
    response = requests.get(api_url, headers=headers)
    # 如果请求成功，解析响应的json数据
    if response.status_code == 200:
        data = response.json()
        # 从数据中提取创建时间，格式为ISO 8601
        created_at = data["commit"]["author"]["date"]
        # 返回创建时间
        return created_at
    # 如果请求失败，抛出异常
    else:

        return None


def get_github_issue_create_time(url):
    print("github issue url")
    # 定义请求头，需要提供GitHub的个人访问令牌
    headers = {
        "Authorization": "bearer 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",
        "Content-Type": "application/json"
    }
    request_url = url.replace("github.com", "api.github.com/repos")
    # 发送GET请求，获取响应
    response = requests.get(request_url, headers=headers)

    # 解析响应，获取JSON数据
    data = response.json()

    # 获取issue的创建时间
    if response.status_code == 200:
        created_at = data["created_at"]
        return created_at

    else:
        return None


def get_github_pull_time(url):
    print("github pull url")
    # 从pull request的url中提取仓库的owner，name和number
    # 定义GitHub的API地址，传入owner，name和number
    api_url = url.replace("github.com", "api.github.com/repos").replace("pull", "pulls")
    # api_url = f'https://api.github.com/repos/ipython/ipython/pulls/8429'
    headers = {
        "Authorization": "bearer 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",
        "Content-Type": "application/json"
    }
    # 发送GET请求，获取pull request的信息
    response = requests.get(api_url, headers=headers)
    # 如果请求成功，解析响应的json数据
    if response.status_code == 200:
        data = response.json()
        # 从数据中提取创建时间，格式为ISO 8601
        created_at = data["created_at"]
        # 返回创建时间
        return created_at
    # 如果请求失败，抛出异常
    else:
        return None


def get_netapp_create_time(url):
    print("cannot find netapp create time")
    return None


def get_debian_create_time(url):
    print("debian cannot find create time")
    pass


def get_snyk_create_time(vuln_url):
    print("snyk url")
    # 发送get请求，获取漏洞的页面内容
    response = requests.get(vuln_url)
    # 判断请求是否成功
    if response.status_code == 200:
        # 获取页面的文本内容
        html = response.text
        # 创建一个BeautifulSoup对象，用于解析html文档
        soup = BeautifulSoup(html, "html.parser")
        # 在文档中查找发布时间的标签，它的格式是<div class="card__header__meta"><span>...</span><span>...</span></div>
        # 我们可以用select方法，根据标签的类名和层级关系，找到对应的标签
        tag = soup.find("li", label="published")
        # 获取标签的文本内容，它就是发布时间
        vuln_time = tag.get_text()
        # 定义一个字典，存储月份的英文缩写和数字的对应关系
        # 把发布时间的字符串按空格分割，得到一个列表，它的格式是["Published", "6", "Feb,", "2012"]
        parts = vuln_time.split()
        # 从列表中提取年，月，日的信息，转换为整数
        year = int(parts[3])
        month = months[parts[2]]  # 去掉月份后面的逗号
        day = int(parts[1])
        # 创建一个datetime对象，表示发布时间
        # vuln_datetime = datetime.strptime(f'{year} {month} {day}', "%Y %m %d")
        # 返回发布时间
        return f'{year} {month} {day}'
    else:
        # 请求失败，返回None
        return None


def get_openwall_create_time(url):
    print("openwall url")
    day = url.split("/")[-2]
    month = url.split("/")[-3]
    year = url.split("/")[-4]
    # vuln_datetime = datetime.strptime(f'{year} {month} {day}', "%Y %m %d")
    return f'{year} {month} {day}'


def get_apache_create_time(url):
    print("apache url")
    response = requests.get(url)

    if response.status_code == 200:
        # 解析网页内容，使用html.parser作为解析器
        soup = BeautifulSoup(response.text, "html.parser")

        # 查找<meta name="ajs-issue-created">标签，返回一个Tag对象
        tag = soup.find("dd", {"class": "date user-tz"})

        # 获取标签的content属性，返回一个字符串
        vul_time = tag.attrs['title'].split()[0]
        day = vul_time.split("/")[0]
        month = months[vul_time.split("/")[1]]
        year = f'20{vul_time.split("/")[2]}'
        return f'{year} {month} {day}'
        # vuln_datetime = datetime.strptime(f'{year} {month} {day}', "%Y %m %d")
        # print(vuln_datetime)
        # 打印创建时间
    else:
        # 请求失败，打印错误信息
        return None


def get_git_url_span(date1_obj, date2, format2):
    date1_obj = date1_obj.replace(tzinfo=None)
    date2_obj = datetime.strptime(date2, format2).replace(tzinfo=None)
    date_diff = date1_obj - date2_obj

    # 获取timedelta对象的days属性，表示两个日期之间的天数差值
    date_diff_days = date_diff.days

    return date_diff_days


def get_time_span(date1, format1, date2, format2):
    if date1 == None or date2 == None:
        return 0
    date1_obj = datetime.strptime(date1, format1).replace(tzinfo=None)
    date2_obj = datetime.strptime(date2, format2).replace(tzinfo=None)
    # 计算两个日期对象之间的差值，返回一个timedelta对象
    date_diff = date1_obj - date2_obj

    # 获取timedelta对象的days属性，表示两个日期之间的天数差值
    date_diff_days = date_diff.days

    return date_diff_days


def get_nvd_time(cve_id):
    # 定义一个NVD的API地址，用于查询漏洞信息
    nvd_api = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
    # 拼接完整的URL，加上漏洞编号
    url = nvd_api + cve_id
    # 发送GET请求，获取响应
    response = requests.get(url)
    # 判断响应状态码是否为200，表示成功
    if response.status_code == 200:
        try:
            # 解析响应的JSON数据，获取漏洞公告的发布时间
            publish_date = response.json()["result"]["CVE_Items"][0]["publishedDate"]
            return publish_date

        # 打印漏洞公告的发布时间
        # print(f"The publish date of {cve_id} is {publish_date}")
        except:
            return None
    else:
        # 打印错误信息
        print(f"Error: {response.status_code}")
        return None


cve_url_not_found = {}


def get_time_csv(dir_path):
    find_cves = os.listdir("/data/zy/VulnerCollector/vdb_output/commit")

    # 使用os.listdir()函数，获取目录下的所有文件名
    depth_dataset = csv.reader(open("/data/zy/pythonProject/CVEKnowledgeMap/depth_dataset.csv", "r"))
    depth_cveids = []

    for row in depth_dataset:
        depth_cveids.append(row[0])
    for file_name in os.listdir(dir_path):
        # 如果文件名以.csv结尾，添加到列表中
        if file_name.endswith(".csv") and file_name.replace('.csv', '') in depth_cveids and file_name.replace('.csv',
                                                                                                              '.txt') in find_cves:
            # 遍历列表中的每个文件名
            # 使用os.path.join()函数，拼接出完整的文件路径
            file_path = os.path.join(dir_path, file_name)
            urls = set()
            cve_id = file_name.replace(".csv", "")
            nvd_time = ""

            # 打开每个文件，按行读取内容
            with open(file_path, "r") as f:
                reader = csv.reader(f)

                for row in reader:
                    if row[0] == "NVD":
                        nvd_time = row[1]
                        continue
                    urls.add(row[2])
            if nvd_time == "":
                nvd_time = get_nvd_time(cve_id)
            url_max_date_format = get_max_url_time(cve_id, urls, nvd_time)
            if url_max_date_format.__len__() ==0:
                continue
            commit_dates = read_commit_file_date(cve_id)
            if not commit_dates:
                continue
            for commit_date in commit_dates:
                span = get_git_url_span(commit_date, url_max_date_format[0], url_max_date_format[1])
                if span < 0:
                    print(commit_date)
                    output_file = open(f'/data/zy/VulnerCollector/cve/min_span/{cve_id}.csv', "a+")
                    output_writer = csv.writer(output_file)
                    output_writer.writerow([commit_date, url_max_date_format[0], span])

            f.close()


def read_commit_file_date(cve_id):
    with open(f'/data/zy/VulnerCollector/vdb_output/commit/{cve_id}.txt', "r") as f:
        content = f.read()
        dates = []
        for line in content.split("\n"):
            if line.__contains__("commit"):
                m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', line)
                if m == None:
                    continue
                sha = m.group(3)
                back = get_commit_date(sha, cve_id)
                if not back:
                    return back
                dates.append(back)
        return dates


# def get_time_txt(dir_path):
#     exist = os.listdir("/data/zy/VulnerCollector/cve/min_span")
#     # 使用os.listdir()函数，获取目录下的所有文件名
#     for file_name in os.listdir(dir_path):
#         # 如果文件名以.txt结尾，添加到列表中
#         if file_name.endswith(".txt") and file_name.replace(".txt", ".csv") not in exist:
#             # 遍历列表中的每个文件名
#             # 使用os.path.join()函数，拼接出完整的文件路径
#             file_path = os.path.join(dir_path, file_name)
#             nvd_time = None
#
#             with open("/data/zy/VulnerCollector/pipeline/pipe0/" + file_name.replace(".txt", ".pkl"),
#                       "rb") as f:
#                 # 使用pickle模块的load函数，从文件中读取Python对象
#                 cve_patches_obj = pickle.load(f)
#                 nvd_time = cve_patches_obj.CVEID
#
#             # 打开每个文件，按行读取内容
#             with open(file_path, "r") as f:
#                 urls = list()
#
#                 for line in f:
#                     # pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z"
#                     # 在字符串中查找匹配的部分，返回一个match对象，如果没有匹配，返回None
#                     # match = re.search(pattern, line)
#                     # 判断是否有匹配
#                     # if match:
#                     #     # 获取匹配的部分，它就是时间
#                     #     # 返回时间
#                     #
#                     #     nvd_time = match.group()
#                     # else:
#                     # nvd_time = get_nvd_time(file_name.replace(".txt", ""))
#                     pattern2 = r"(https?://\S+)"
#                     match = re.search(pattern2, line)
#                     if match:
#                         urls.append(match.group())
#                 # if urls.__len__()>0:
#                 max_time = get_max_url_time(file_name.replace(".txt", ""), urls, nvd_time)
#                 print(max_time)
#                 commit_file = open()
#                 # else:
#                 #     print(file_name.replace(".txt", ""))


count = 0
not_find = []


def get_max_url_time(cveid, urls, nvd_time):
    min_span = 100000
    cve_url_not = []
    global count
    intermediate_file = open(f'/data/zy/VulnerCollector/cve/pipeline/{cveid}.pkl', "wb")
    url_date = []
    max_time = ""
    for url in urls:
        if re.search("bugzilla.redhat.com/show_bug.cgi", url):

            time = get_redhat_create_time(url)
            if time == None:
                cve_url_not.append(url)
                continue
            span = get_time_span(time, "%Y-%m-%d", nvd_time, "%Y-%m-%dT%H:%MZ")
            if span < min_span:
                min_span = span
                max_time = [time, "%Y-%m-%d"]

            url_date.append((url, time))
        elif re.search("snyk.io", url):
            time = get_snyk_create_time(url)
            if time == None:
                cve_url_not.append(url)
                continue
            span = get_time_span(time, "%Y %m %d", nvd_time, "%Y-%m-%dT%H:%MZ")
            if span < min_span:
                min_span = span
                max_time = [time, "%Y %m %d"]

            url_date.append((url, time))

        elif re.search("openwall.com", url):
            time = get_openwall_create_time(url)
            if time == None:
                cve_url_not.append(url)
                continue
            span = get_time_span(time, "%Y %m %d", nvd_time, "%Y-%m-%dT%H:%MZ")
            if span < min_span:
                min_span = span
                max_time = [time, "%Y %m %d"]

            url_date.append((url, time))


        elif re.search("issues.apache.org/jira/browse", url):
            time = get_apache_create_time(url)
            if time == None:
                cve_url_not.append(url)
                continue
            span = get_time_span(time, "%Y %m %d", nvd_time, "%Y-%m-%dT%H:%MZ")
            if span < min_span:
                min_span = span
                max_time = [time, "%Y %m %d"]

            url_date.append((url, time))

        # todo netapp debian cannot find published time
        elif re.search("netapp", url):
            time = get_netapp_create_time(url)
        elif re.search("debian", url):
            time = get_debian_create_time(url)
        # else:
        #     output_file = open(f'./cve/not_found_url/{cveid}.csv', "a+")
        #     output_writer = csv.writer(output_file)
        #     output_writer.writerow(
        #         [url])
        #     output_file.close()
    pickle.dump(url_date, intermediate_file)
    return max_time


# txt_path = "/data/zy/VulnerCollector/data/reference_location"
csv_path = "/data/zy/VulnerCollector/data/reference_location"
# get_time_txt(txt_path)
get_time_csv(csv_path)
# 保存cve_url_not_found


print("存在时延的数量：" + str(count))
print(not_find)
