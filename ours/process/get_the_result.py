import csv
import glob
import os
import pickle
import re

import config

# Define the base directories
answer_dir = config.ANSWER_PATH
pipeline_dir = config.PIPILINE_PATH


# Function to read the candidate commits
def read_candidate_commits(folder, patch_number):
    pkl_file = os.path.join(pipeline_dir, folder, 'candidate_commits.pkl')
    with open(pkl_file, 'rb') as file:
        candidate_commits = pickle.load(file)
        return candidate_commits.get(int(patch_number))


def read_the_answer():
    # Iterate over each folder in the answer directory
    for folder in os.listdir(answer_dir):
        folder_path = os.path.join(answer_dir, folder)

        if os.path.isdir(folder_path):
            # Iterate over each file in the folder
            files = glob.glob(f'{folder_path}/answer*')
            frequency_dict = {}
            for file_name in files:
                file_path = os.path.join(folder_path, file_name)
                with open(file_path, 'r') as file:
                    lines = file.readlines()
                    read_lines = False
                    linecount = 0
                    for line in lines:
                        linecount += 1
                        # Check if the line contains the folder name
                        if line.startswith(folder):
                            read_lines = True
                            break
                        # If reading lines, check for the Patch Number

                    for line in lines:

                        if linecount == 0 or not read_lines:
                            read_lines = False
                            if line.startswith('Patch Number:') and re.search('Patch Number', line):
                                # 获得该行的数字
                                if re.search(r'\d+', line) is None:
                                    continue
                                patch_number = re.search(r'\d+', line).group()
                                if not patch_number.isdigit():
                                    continue
                                # 如果找到了，增加出现次数
                                frequency_dict[patch_number] = frequency_dict.get(patch_number, 0) + 1
                        linecount -= 1

            max_frequency = max(frequency_dict.values())
            most_common_values = [key for key, value in frequency_dict.items() if value == max_frequency]
            answer_prompts = []
            for patch_number in most_common_values:
                if not patch_number.isdigit():
                    continue
                answer_prompts.append(read_candidate_commits(folder, patch_number))
                # 保存answer_prompt
            with open(f'{pipeline_dir}/{folder}/answer_prompt.pkl', 'wb') as file:
                pickle.dump(answer_prompts, file)
            with open(f'{pipeline_dir}/{folder}/frequecy.csv', 'w') as file:
                writer = csv.writer(file)
                writer.writerow([folder, most_common_values, max_frequency,answer_prompts])

            print(f'Folder: {folder}, Most common values: {most_common_values}, Highest Frequency: {max_frequency}')


if __name__ == '__main__':
    read_the_answer()
