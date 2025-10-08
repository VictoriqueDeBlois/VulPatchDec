import csv
import json
import os
import re

import config
from pre_process.get_commit_message import get_fixed_version_commits
from util.tool import identify_null_file


def get_cve_list(path):
    with open(path, "r") as f:
        data1 = json.load(f)
        f.close()
    # 获取字典键并存储在一个列表中
    keys1 = list(data1.keys())
    tracer_find_pathc_cve = identify_null_file(config.TRACER_COMMIT_PATH)
    keys = list(set(keys1) | (set(tracer_find_pathc_cve)))

    return keys


def get_vera_found(cve):
    with open(config.VERA_PATH + cve + ".json", "r") as f:
        data = json.load(f)
        artifactComponents = data["artifactComponents"]
        value = {}
        # 遍历artifactComponents数组中的每个元素
        for ac in artifactComponents:
            # 获取ac中的versionRanges数组
            versionRanges = ac["versionRanges"]

            # 遍历versionRanges数组中的每个元素
            for vr in versionRanges:
                # 获取vr中的updateToVersion元素
                updateToVersion = vr["updateToVersion"]

                # 获取vr中的patch元素
                patch = vr["patch"]
                if updateToVersion and updateToVersion not in value.keys():
                    value[updateToVersion] = set()
                if patch:
                    value[updateToVersion].add(patch)
        f.close()

    with open("vera_not_found.csv", "a+") as f:
        writer = csv.writer(f)
        writer.writerow([cve, "json文件不存在"])
        f.close()
    return value


# def get_Tracer_commits(cve):
def compare(cve_list):
    for cve in cve_list:
        if f'{cve}.csv' in os.listdir(config.TRACCER_NOT_MATHCED_PATH):
            continue
        version_commits = get_vera_found(cve)
        if version_commits.__len__() == 0:
            print("version_commits is None : " + cve)
            continue
        for fixed_version in version_commits:
            commits = version_commits[fixed_version]
            if commits.__len__() == 0:
                print(fixed_version + " commit is None : " + cve)
                continue
            print(fixed_version + " commit is not None : " + cve)
            commit = commits.pop()
            commits.add(commit)
            m = re.match(r'https*://github.com/(.+?)/(.+?)/commit/(.+?)', commit)
            if m is None:
                print("m is None : " + cve)

                continue
            owner = m.group(1).lower()
            repo = m.group(2).lower()
            # todo :先找Vul下的git目录
            Vul_git = f'../VulnerCollector/git'
            all_commits = get_fixed_version_commits(owner, repo, fixed_version, f'{Vul_git}{owner}/{repo}', 0)
            # if all_commits is None:
            #     break
            # all_hash = set()
            # for commit in all_commits:
            #     all_hash.add(commit[0])
            # # 检测是否vera找到的commit都在fixed版本-1——fixed版本中
            # for commit in commits:
            #     m = re.match(r'https*://github.com/(.+?)/(.+?)/.+/(.+)', commit)
            #     hash = m.group(3)
            #
            #     if hash not in all_hash:
            #         with open(config.TRACER_COMMIT_PATH + cve + '.csv', 'a+') as f:
            #             writer = csv.writer(f)
            #             writer.writerow([fixed_version, commit])
            #             f.close()


if __name__ == "__main__":
    cve_list = get_cve_list(config.DBA_CVEID_PATH)
    compare(cve_list)
