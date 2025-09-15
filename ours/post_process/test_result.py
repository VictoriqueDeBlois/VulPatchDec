# import glob
# import re
#
# # 定义要搜索的目录
# directory = '/data/zy/pythonProject/CVEKnowledgeMap/answer/CVE-2014-3248/'
#
# # 使用glob模块查找所有以'answer'开头的文件
# file_list = glob.glob(f'{directory}answer*')
# #数组记录出现次数和查找包含'Patch Number'的行
# frequency_dict = {}
#
# # 遍历文件列表
# for file_path in file_list:
#     with open(file_path, 'r') as file:
#         # 读取文件的每一行
#         for line in file:
#             # 使用正则表达式查找包含'Patch Number'的行
#             if re.search('Patch Number', line):
#                 #获得该行的数字
#                 patch_number = re.search(r'\d+', line).group()
#                 # 如果找到了，增加出现次数
#                 frequency_dict[patch_number] = frequency_dict.get(patch_number, 0) + 1
#
# # 找到出现频度最高的值
# highest_frequency = max(frequency_dict.values())
# most_common_values = [key for key, value in frequency_dict.items() if value == highest_frequency]
# print(most_common_values)
# print(highest_frequency)