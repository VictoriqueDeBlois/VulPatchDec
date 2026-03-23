import os
import threading

import requests
import csv
import time
import datetime

results = []
# Github API token
TOKEN = os.environ.get("GITHUB_TOKEN", "")
# ToKEN = os.environ.get("GITHUB_TOKEN", "")
# Github API URL
URL = 'https://api.github.com/search/repositories'

date_limit = "2023-10-31"
data_end = "2024-11-30"

# Headers for the CSV file
# CSV_HEADERS = ['Repository Name', 'URL', 'Stars', 'Owner', 'Parent']
CSV_HEADERS = ['Repository Name', 'URL', 'Stars', 'Owner','Language']

# A variable to store the last number of stars
last_stars = 0


# Function to write the results to a CSV file
def write_to_csv(name, repos):
    with open(name, 'a+', newline='') as file:
        writer = csv.writer(file)
        for repo in repos:
            # parent = repo["parent"]["full_name"] if "parent" in repo else "None"

            writer.writerow([repo['name'], repo['html_url'], repo['stargazers_count'], repo["owner"]["login"],repo["language"]])


# Main function
def get_repos_time(star,starttime):
    headers = {'Authorization': f'token {TOKEN}'}
    page = 1
    while True:
        try:
            if starttime>=data_end:
                break

            original_date_obj = datetime.datetime.strptime(starttime, "%Y-%m-%d")

                # 使用 datetime 库的 timedelta 函数，创建一个表示 3 年的时间间隔对象
            three_years = datetime.timedelta(days=365 * 3)

                # 使用加法运算符，将原始日期对象和时间间隔对象相加，得到新的日期对象
            new_date_obj = original_date_obj + three_years

                # 使用 datetime 库的 strftime 函数，将新的日期对象转换为字符串
            new_date = new_date_obj.strftime("%Y-%m-%d")
            print(f'starttime: {starttime} endtime:{new_date}')
            if new_date >data_end:
                new_date = data_end
            PARAMS = {
                'q': f'stars:{star} created:{starttime}..{new_date}',
                'sort': 'stars',
                'order': 'desc',
                'per_page': 100,
                'page': 1
            }

            PARAMS['page'] = page
            response = requests.get(URL, headers=headers, params=PARAMS)

            result = response.json()
            if result['total_count'] == 0:
                get_repos_time(star,new_date)


            if 'items' not in result or not result['items']:
                break

            repos = result['items']
            valid_repos = []
            print(f'Page {page} - {len(repos)} repos ')

            for repo in repos:
                valid_repos.append(repo)
            results.extend(valid_repos)
            write_to_csv("temp.csv", valid_repos)
            if 'next' in response.links:
                # Get the next page number from the link URL
                page += 1

            else:
                time.sleep(10)  # To prevent hitting rate limit
                # 使用 datetime 库的 strptime 函数，将字符串转换为 datetime 对象
                get_repos_time(star,new_date)
                break

        except Exception as e:
            print(e)
            time.sleep(30)  # To prevent hitting rate limit
def get_repos(max_star, min_star, peek, p):
    headers = {'Authorization': f'token {TOKEN}'}
    page = 1
    while True:
        try:
            if peek == 0:
                break
            low_star = max_star - peek
            if max_star < min_star:
                break
            if low_star < min_star:
                low_star = min_star
            PARAMS = {
                'q': f'stars:{low_star}..{max_star} created:>{date_limit}',
                'sort': 'stars',
                'order': 'desc',
                'per_page': 100,
                'page': 1
            }
            PARAMS['page'] = page
            response = requests.get(URL, headers=headers, params=PARAMS)
            result = response.json()

            if 'items' not in result or not result['items']:
                break
            if result['total_count'] > 1000:
                time.sleep(2 * p)  # To prevent hitting rate limit
                if peek / 2 >= 1:
                    get_repos(max_star, min_star, peek / 2, p)
                break

            repos = result['items']
            valid_repos = []
            print(f'Page {page} - {len(repos)} repos Max: {max_star} Min: {low_star} peek: {peek}')
            for repo in repos:
                valid_repos.append(repo)
            results.extend(valid_repos)
            write_to_csv("temp_" + str(p) + ".csv", valid_repos)
            if 'next' in response.links:
                # Get the next page number from the link URL
                page += 1

            else:
                time.sleep(10 + p)  # To prevent hitting rate limit
                peek = max_star-low_star
                get_repos(low_star-1, min_star, peek, p)
                break

        except Exception as e:
            print(e)
            time.sleep(30)  # To prevent hitting rate limit

for i in range(100,301):
    get_repos_time(i,date_limit)
# 创建三个线程对象，分别传入不同的参数字典
# t0 = threading.Thread(target=get_repos, args=(265, 100, 4, 5), )
# t1 = threading.Thread(target=get_repos, args=(25000, 10000, 5000, 1), )
# t2 = threading.Thread(target=get_repos, args=(10000, 1000, 1000, 2), )
# t3 = threading.Thread(target=get_repos, args=(1000, 500, 100, 3), )
# t4 = threading.Thread(target=get_repos, args=(10000, 9971, 250, 1))

# # 启动三个线程
# t0.start()
# t1.start()
# t2.start()
# t3.start()
# t4.start()
#
# # 等待三个线程结束
# t0.join()
# t1.join()
# t2.join()
# t3.join()
# t4.join()

# 打印结束提示语
print("All threads finished.")
