import csv
import json

def get_snyk_found(url):
    value = {}
    try:
        with open(url, "r") as f:
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
                    if updateToVersion and updateToVersion not in value.keys() and patch:
                        value[updateToVersion] = set()
                        value[updateToVersion].add(patch)

            f.close()

    except:
        print(f'{url} snyk not found')
    return value