import csv

import config

def extend_github_commit_node(answer_commits_lines,cveid):
    repo_file = open(f'{config.TEST_PATH}{cveid}/repo_config.csv', "r")
    reader = csv.reader(repo_file)
    first_row = next(reader)
    owner = first_row[0]
    repo = first_row[1]
    git_repo_path = f'{config.GIT_REPO_PATH}{owner}/{repo}'
    #拼接commit
    for answer_commit_line in answer_commits_lines:
        answer_commits = f'https*://github.com/{owner}/{repo}/{answer_commit_line[0]}'
        #获取answer_commits的data
        