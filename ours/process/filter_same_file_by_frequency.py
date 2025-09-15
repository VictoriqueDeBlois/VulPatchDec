import pickle

import config

import os
import csv
from collections import defaultdict


import os
import csv
from collections import defaultdict


# csv.field_size_limit(500 * 1024 * 1024)

def filter_same_patch(folders,path):
    # 创建一个字典来存储每个值的出现频度

    # 遍历文件夹
    for folder in folders.copy():
        frequency_dict = defaultdict(int)
        print(f"Processing {folder}")
        # folder = "CVE-2019-3851"
        folder_path = os.path.join(path, folder)
        same_patch_file_path = os.path.join(folder_path, 'same_patch.csv')

        # 如果same_patch.csv存在，则删除
        if os.path.exists(same_patch_file_path):
            os.remove(same_patch_file_path)

        # 获取文件夹下的所有文件
        files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
        if "repo_config.csv" in files:
            files.remove("repo_config.csv")

        # 遍历文件夹中的所有文件
        for file in files:
            seen_lines = set()  # 用于跟踪每个文件中已经计算过的行
            with open(os.path.join(folder_path, file), 'r') as f:
                try:
                    reader = csv.reader(f)

                    for line in reader:
                        try:
                            if len(line) < 3 or tuple(line[:3]) in seen_lines:
                                continue
                            # 对于每一列的值，如果它们是新的，则增加频度
                            for value in line[:2]:
                                frequency_dict[value] += 1
                            seen_lines.add(tuple(line[:3]))  # 将这一行添加到已见集合中
                        except IndexError:
                            print(f'Error in {file}: {line}')
                except csv.Error as e:
                    print(f'Error in {file}: {e} {folder}')
                except UnicodeDecodeError as e:
                    print(f'Error in {file}: {e}  {folder}')

        # 找到出现频度最高的值
        if len(frequency_dict) == 0:
            print(f'No data in {folder}')
            continue
        highest_frequency = max(frequency_dict.values())
        most_common_values = [key for key, value in frequency_dict.items() if value == highest_frequency]

        # 写入same_patch.csv文件
        with open(same_patch_file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            same_lines = set()
            for file in files:
                with open(os.path.join(folder_path, file), 'r') as f:
                    try:
                        reader = csv.reader(f)
                        try:
                            for line in reader:
                                # 检查line中的任何值是否在最常见值列表中
                                if any(value in most_common_values for value in line[:3]):
                                    if(len(line) < 3 or tuple(line[:3]) in same_lines):
                                        continue
                                    same_lines.add(tuple(line[:3]))
                                    writer.writerow(line)
                        except csv.Error as e:
                            continue
                    except UnicodeDecodeError as e:
                        pass




    return folders



if __name__ == '__main__':
    folders = os.listdir(config.OUTPUT_PATH)
    # folders = ['CVE-2020-9548']
    folders = filter_same_patch(folders,config.OUTPUT_PATH)
    print("finish")
