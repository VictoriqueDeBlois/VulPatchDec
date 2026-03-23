"""
-----------------------------------------
@Created: 2023/12/25
------------------------------------------
@Modify: 2023/12/25
------------------------------------------
@Description:
定义相关配置
"""
import inspect
import os
import sys

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))+ "/"
parent_dir = os.path.dirname(current_dir)
PROJECT_ROOT = parent_dir.rstrip('/') + '/'
CURRENT_DIR = current_dir.rstrip('/') + '/'

print('PROJECT_ROOT', PROJECT_ROOT)
print('current_dir', current_dir)


RESOURCE_PATH = current_dir + 'resource/'
OUTPUT_PATH = current_dir + 'output/'
OUTPUT_PATH2 = current_dir + 'output2/'

TEST_PATH = current_dir + 'test/'
TEST_PATH2 = current_dir + 'test2/'
NEWTEST_PATH = current_dir + 'newtest/'
# TEMP_PATH = current_dir + '/temp/'
CVE_SETS_PKL = '../pythonProject/CVEKnowledgeMap/cves_set.pkl'
CVE_SETS_TEST_PATH = '../pythonProject/CVEKnowledgeMap/test_311/'
DBA_CVEID_PATH = '../VulnerCollector/data/dataset/breadth_dataset-DBA_CVEIDs_withPatches.json'


RELATED_PATH = '../pythonProject/CVEKnowledgeMap/related/'
DBB_CVEID_PATH = '../VulnerCollector/data/dataset/breadth_dataset-DBB_CVEIDs_withPatches.json'
DBA_CVEID_PATH = '../VulnerCollector/data/dataset/breadth_dataset-DBA_CVEIDs_withPatches.json'
VERA_PATH = "../VulnerCollector/vera/result/"
CVE_RESULT_PATH = CURRENT_DIR + 'cve_old/'
TRACCER_NOT_MATHCED_PATH = CURRENT_DIR + 'cve/vera_commit_not_match/'
TRACER_COMMIT_PATH = '../VulnerCollector/vdb_output/commit/'
TRACER_COMMIT__META_PATH = '../VulnerCollector/vdb_output/commit_meta/'
GIT_REPO_PATH = '../VulnerCollector/git/'
TEMP_PATH = '../VulnerCollector/temp_commit/'
SNYK_JSON_PATH = ''
CVE_DATA_PATH = '../VulnerCollector/data/CVE/DataSet-NVD/'
PRODU_VER = '../pythonProject/CVEKnowledgeMap/cve/product_version/'
LOG_PATH = CURRENT_DIR + 'log/'
#todo 测试100个
ANSWER_PATH = CURRENT_DIR + 'answer/'
ANSWER_PATH2 = CURRENT_DIR + 'answer2/'
token = os.environ.get("GITHUB_TOKEN", "")
#存放补丁结果的路径
RESULT_PATH = CURRENT_DIR + 'result/'
PIPILINE_PATH = '../pythonProject/CVEKnowledgeMap/pipeline/'
#存放CVE中间结果的路径
CVE_PATH = CURRENT_DIR + 'cve/'
ALL_COMMITS_PATH = '../pythonProject/CVEKnowledgeMap/all_commits/'
DATA_CVE = ''
Batch_Size = 50