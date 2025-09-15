import csv
import json




def get_vera_found(url):
    value = {}
    try:
        with open(url, "r") as f:
            data = json.load(f)
            artifactComponents = data["components"]
            value = {}
            # 遍历artifactComponents数组中的每个元素
            for ac in artifactComponents:
                # 获取ac中的versionRanges数组
                versionRanges = ac["versions"]

                # 遍历versionRanges数组中的每个元素
                for vr in versionRanges:
                    # 获取vr中的updateToVersion元素
                    updateToVersion = vr["fix_version"]

                    # 获取vr中的patch元素
                    patch = vr["patch"]
                    if updateToVersion and updateToVersion not in value.keys() and patch and patch != '':
                        value[updateToVersion] = set()
                        value[updateToVersion].add(patch)

            f.close()

    except:
        print(f'{url} vera not found')
    return value