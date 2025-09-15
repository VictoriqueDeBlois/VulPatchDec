import pandas as pd
from collections import defaultdict
import subprocess

# 读取CSV文件
csv_file = '../resource/depth_dataset.csv'
df = pd.read_csv(csv_file, header=None)

# 设置列名称
df.columns = ['CVE_ID', 'Empty', 'Empty2', 'Commit_URL']

# 删除空列
df = df.drop(['Empty', 'Empty2'], axis=1)

# 创建一个字典以存储每个CVE_ID对应的提交URL
cve_commit_dict = defaultdict(list)

# 将提交按CVE_ID分组
for _, row in df.iterrows():
    cve_id = row['CVE_ID']
    commit_url = row['Commit_URL']
    cve_commit_dict[cve_id].append(commit_url)

# 判断两条提交是否等价的函数
def are_commits_equivalent(commit1, commit2, repo_path='/path/to/your/repo'):
    """
    使用 git diff 比较两个提交是否等价
    如果两个提交之间没有差异，认为它们是等价的
    :param commit1: 第一个提交的哈希
    :param commit2: 第二个提交的哈希
    :param repo_path: 本地 Git 仓库的路径
    :return: 如果提交没有差异返回 True，否则返回 False
    """
    try:
        # 获取两个提交之间的差异
        diff_command = ["git", "diff", commit1, commit2]
        result = subprocess.run(diff_command, cwd=repo_path, capture_output=True, text=True)

        # 如果没有差异，返回 True，表示等价
        if result.returncode == 0 and not result.stdout.strip():
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error while running git diff: {e}")
        return False

# 创建一个集合来存储等价提交对
equivalent_commits = set()

# 对每个CVE ID，判断提交是否等价
for cve_id, commits in cve_commit_dict.items():
    for i in range(len(commits)):
        for j in range(i + 1, len(commits)):
            commit1 = commits[i]
            commit2 = commits[j]
            if are_commits_equivalent(commit1, commit2, repo_path='/path/to/your/repo'):
                # 将等价的提交添加到集合中
                equivalent_commits.add((commit1, commit2))

# 输出等价提交的集合
print(f"等价提交对: {equivalent_commits}")
