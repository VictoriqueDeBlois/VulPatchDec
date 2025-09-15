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

current_dir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
PROJECT_ROOT = parent_dir.rstrip('/') + '/'
CURRENT_DIR = current_dir.rstrip('/') + '/'
print('PROJECT_ROOT', PROJECT_ROOT)
print('current_dir', current_dir)

OUTPUT_PATH = current_dir + '/output/'

TEST_PATH = current_dir + '/test/'

CVE_SETS_PKL = '/data/zy/pythonProject/CVEKnowledgeMap/cves_set.pkl'
CVE_SETS_TEST_PATH = '/data/zy/pythonProject/CVEKnowledgeMap/test_311/'
DBA_CVEID_PATH = '/data/zy/VulnerCollector/data/dataset/breadth_dataset-DBA_CVEIDs_withPatches.json'

DBB_CVEID_PATH = '/data/zy/VulnerCollector/data/dataset/breadth_dataset-DBB_CVEIDs_withPatches.json'
DBA_CVEID_PATH = '/data/zy/VulnerCollector/data/dataset/breadth_dataset-DBA_CVEIDs_withPatches.json'
VERA_PATH = "/data/xuhaoran/pycharm/testvul/vera/detail/"
CVE_RESULT_PATH = CURRENT_DIR + 'cve_old/'
TRACCER_NOT_MATHCED_PATH = CURRENT_DIR + 'cve/vera_commit_not_match/'
TRACER_COMMIT_PATH = '/data/zy/VulnerCollector/vdb_output/commit/'
GIT_REPO_PATH = '/data/zy/VulnerCollector/git/'
SNYK_JSON_PATH = '/data/xuhaoran/pycharm/testvul/snyk/search'
CVE_DATA_PATH = '/data/zy/VulnerCollector/data/CVE/DataSet-NVD/'
LOG_PATH = CURRENT_DIR + 'log/'
ANSWER_PATH = CURRENT_DIR + 'answer/'
token = "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"
#存放补丁结果的路径
RESULT_PATH = CURRENT_DIR + 'result/'
PIPILINE_PATH = CURRENT_DIR + 'pipeline/'
#存放CVE中间结果的路径
CVE_PATH = CURRENT_DIR + 'cve/'
