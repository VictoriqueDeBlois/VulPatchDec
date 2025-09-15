import concurrent.futures
import datetime
import os.path
import queue
import threading
import traceback

from tqdm import tqdm

from vulnerability_analysis.patch_localization.tool.cls_cve_localized_patch import CVELocalizedPatch
from vulnerability_analysis.patch_localization.tool.tool_main import read_cve_patch_result, \
    generate_localized_CVE_patch_result_with_rules
from .cve_search import init_and_read_NRD, deep_search_url, search_commit, extend_commit
from .read_vdb import VDBreader
from .util import Base


class Tracer(Base):
    def __init__(self, logger=None, log_path=None):
        super().__init__(logger=logger, log_path=log_path)
        self.current_bar = None
        self.pipe_end = None
        self.pipe_start = None
        self.processes = None
        self.vdb = VDBreader(logger=logger, log_path=log_path)
        self.vdb.read_vdb()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=10, thread_name_prefix='timer')

    def pipeline(self, func, queue_in, queue_out, path):
        os.makedirs(path, exist_ok=True)
        while True:
            task = queue_in.get()
            if task is None:
                queue_out.put(None)
                break
            last_path, cve_id, consuming_time = task
            begin = datetime.datetime.now()
            if os.path.exists(os.path.join(path, f'{cve_id}.pkl')):
                end = datetime.datetime.now()
                time = end - begin + consuming_time
                queue_out.put((path, cve_id, time))
                continue
            if last_path is None:
                cve_patches_obj = cve_id
            else:
                cve_patches_obj = CVELocalizedPatch.load(last_path, cve_id)
            try:
                future = self.executor.submit(func, cve_patches_obj)
                cve_patches_obj = future.result(60 * 20)
            except concurrent.futures.TimeoutError:
                self._logger.error('%s at %s time out', str(cve_id), func.__name__)
                continue
            except Exception as e:
                self._logger.error('%s at %s error: %s', str(cve_id), func.__name__, e.__str__())
                self._logger.error(traceback.format_exc())
                continue
            cve_patches_obj.save(path)
            end = datetime.datetime.now()
            time = end - begin + consuming_time
            queue_out.put((path, cve_id, time))

    def start_pipeline(self):
        queue0 = queue.Queue(maxsize=10)
        queue1 = queue.Queue()
        queue2 = queue.Queue()
        queue3 = queue.Queue()
        queue4 = queue.Queue()

        self.processes = [
            threading.Thread(target=Tracer.pipeline,
                             args=(self, init_and_read_NRD, queue0, queue1, './pipeline/pipe0'),
                             name='init_and_read'),
            threading.Thread(target=Tracer.pipeline,
                             args=(self, deep_search_url, queue1, queue2, './pipeline/pipe1'),
                             name='deep_search'),
            threading.Thread(target=Tracer.pipeline,
                             args=(self, search_commit, queue2, queue3, './pipeline/pipe2'),
                             name='search_commit'),
            threading.Thread(target=Tracer.pipeline,
                             args=(self, extend_commit, queue3, queue4, './pipeline/pipe3'),
                             name='extend_commit')
        ]

        [p.start() for p in self.processes]
        self._logger.info('start pipeline')

        self.pipe_start = queue0
        self.pipe_end = queue4

    def feed_cve(self, find_lang):
        tasks = []
        for lang in self.vdb.lang_list["repo_vul_list"]:
            lang_str = lang["lang"]
            if lang_str not in find_lang:
                continue
            self._logger.info("start lang %s", lang["lang"])

            for repo in lang['repo_list']:
                repo_name = repo['repo']
                cve_list = self.vdb.find_repo(repo_name)
                if cve_list is None:
                    self._logger.error("cannot find %s", repo_name)
                    continue
                for cve in cve_list:
                    if os.path.exists(f'./vdb_output/commit/{cve}.txt'):
                        continue
                    tasks.append(cve)
        self.current_bar = tqdm(total=len(tasks), desc='task')
        for cve in tasks:
            self.pipe_start.put((None, cve, datetime.timedelta()))
        self.pipe_start.put(None)

    def find_patch(self):
        while True:
            result = self.pipe_end.get()
            if result is None:
                self.current_bar.close()
                break
            last_path, cve_id, consuming_time = result
            self._logger.info("%s finished, consuming time: %s", cve_id, consuming_time)
            cve_patches_obj = read_cve_patch_result(cve_id)
            fig_path = os.path.join('./vdb_output/graph', f'{cve_id}.pdf')

            try:
                future = self.executor.submit(cve_patches_obj.url_graph.visualise_graph,
                                              save_fig=True, save_fig_path=fig_path)
                future.result(20)
            except concurrent.futures.TimeoutError:
                future.cancel()
                self._logger.error('%s at %s time out', str(cve_id), 'visualise_graph')
            except Exception as e:
                self._logger.error("%s at %s error: %s | can't draw graph", str(cve_id), 'visualise_graph', e.__str__())
                self._logger.error(traceback.format_exc())

            rules = {'src': ['all'], 'priority': 'CN', 'select_add_SG_N': True, 'Extension': 30,
                     'searched_entities': ['all'], 'limited_patch_num': False, 'valid_expansion_message': True,
                     'patch_type': ['git_commit', 'svn'], 'patch_content': ['only_code_change',
                                                                            'cutoff=4']}
            try:
                patches_in_node = generate_localized_CVE_patch_result_with_rules(cve_id, rules)[cve_id]
            except Exception as e:
                self._logger.error("%s can't find patch", cve_id)
                self._logger.error(traceback.format_exc())
                continue

            urls = []
            for ele in patches_in_node:
                urls.append(ele.formatted_url)
                self._logger.info('The localized patches for %s are: %s', cve_id, ele.formatted_url)

            with open(f'./vdb_output/commit/{cve_id}.txt', 'w', encoding='utf-8') as fp:
                fp.write('\n'.join(urls))

            self.current_bar.update()

    def start(self, find_lang):
        self.start_pipeline()
        find_patch_thread = threading.Thread(target=Tracer.find_patch, args=(self,), name='find_patch')
        find_patch_thread.start()
        self.feed_cve(find_lang)
        find_patch_thread.join()
        [p.join() for p in self.processes]
        self.executor.shutdown()

    def test(self, cve):
        self.current_bar = tqdm(total=1, desc='task')
        self.start_pipeline()
        find_patch_thread = threading.Thread(target=Tracer.find_patch, args=(self,), name='find_patch')
        find_patch_thread.start()
        self.pipe_start.put((None, cve, datetime.timedelta()))
        self.pipe_start.put(None)
        find_patch_thread.join()
        [p.join() for p in self.processes]
        self.executor.shutdown(wait=False, cancel_futures=True)

    def run_list(self, cve_list):
        self.current_bar = tqdm(total=len(cve_list), desc='task')
        self.start_pipeline()
        find_patch_thread = threading.Thread(target=Tracer.find_patch, args=(self,), name='find_patch')
        find_patch_thread.start()
        for cve in cve_list:
            self.pipe_start.put((None, cve, datetime.timedelta()))
        self.pipe_start.put(None)
        find_patch_thread.join()
        [p.join() for p in self.processes]
        self.executor.shutdown()
