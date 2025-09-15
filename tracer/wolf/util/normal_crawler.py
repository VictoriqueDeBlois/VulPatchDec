import queue
import threading
import time

import requests

from .base import Base


class BaseCrawler(Base):
    def __init__(self, logger=None, log_path=None):
        super().__init__(logger=logger, log_path=log_path)
        self.session = requests.session()
        self.auth_available = True

    @property
    def headers(self):
        return {}

    @property
    def available(self):
        return self.auth_available

    def get(self, url):
        try:
            self._logger.info('url: %s', url.__str__())
            response = self.session.get(url, headers=self.headers, timeout=10)
            if response:
                content = response.text
                response.close()
                return content, 'done', 0
            elif response.status_code == 404:
                self._logger.warning('status_code 404, ' + url.__str__())
                return False, 'pass', 0
            elif response.status_code == 400:  # url参数无效
                self._logger.warning('status_code 400, ' + url.__str__())
                return False, 'pass', 0
            elif response.status_code == 422:
                # 422, 是没找到，如：https://api.github.com/repos/spring-projects/spring-framework/commits/03f547
                self._logger.warning('status_code 422, ' + url.__str__())
                return False, 'pass', 0
            elif response.status_code == 410:
                self._logger.warning('status_code 410, ' + url.__str__())
                return False, 'pass', 0
            elif response.status_code == 403:
                self._logger.warning('status_code 403, ' + url.__str__())
                return False, 'pass', 0
            elif response.status_code == 401:
                # token 失效
                self._logger.warning('status_code 401, ' + url.__str__())
                # self.auth_available = False
                return False, 'pass', 0
            elif response.status_code == 406:
                self._logger.warning('status_code 406, ' + url.__str__())
                return False, 'pass', 0
            else:  # 爬虫出错
                self._logger.error('unknown network error, status_code %s, %s', response.status_code.__str__(),
                                   url.__str__())
                return False, 'wait', 60
        except requests.exceptions.Timeout:
            self._logger.error('time out, %s', url.__str__())
            return False, 'retry', 0
        except Exception as e:
            self._logger.error('unknown error' + e.__str__())
            self._logger.debug(e)
            return False, 'all wait', 60


class BaseCrawlerPool(Base):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(BaseCrawlerPool, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance

    def __init__(self, logger=None, log_path=None):
        if self.initialized:
            return
        self.initialized = True
        super().__init__(logger=logger, log_path=log_path)
        self.pool: list[BaseCrawlerPool]
        self.pool = list()
        self.task_queue = queue.Queue()
        self.result_queue = queue.Queue()

    def __del__(self):
        for _ in range(len(self.pool)):
            self.result_queue.put(None)

    def load_base_info(self, info):
        logger_name = self._logger.name
        info = list(info)
        info += [None]
        for i, authorization in enumerate(info):
            crawler = BaseCrawler(logger=logger_name)
            sub_thread = BaseCrawlerThread(crawler, self.task_queue, name=f'base_crawler{i}')
            self.pool.append(sub_thread)
        self._start()

    def _start(self):
        for thread in self.pool:
            thread.start()

    def stop(self):
        for _ in self.pool:
            self.task_queue.put(None)
        for thread in self.pool:
            thread.join()
        self.pool.clear()

    def get(self, url, retry=3):
        task_done = threading.Event()
        result = []
        self.task_queue.put((url, retry, task_done, result))
        task_done.wait()
        return result[0]


class BaseCrawlerThread(threading.Thread):
    def __init__(self, crawler: BaseCrawler,
                 task_queue: queue.Queue,
                 name=None):
        threading.Thread.__init__(self, name=name)
        self.task_queue = task_queue
        self.crawler = crawler
        self.wait_event = threading.Event()
        self.wait_event.set()

    def run(self) -> None:
        while True:
            self.wait_event.wait()
            task = self.task_queue.get()
            if task is None:
                break
            url, retry_time, task_done, container = task
            if retry_time <= 0:
                # self._logger.debug("retry too many, url: %s", url)
                container.append(False)
                task_done.set()
                continue
            result = self.crawler.get(url)
            # result: false, content (是否成功), 指令, 等待时间
            content, instruct, wait_time = result

            if content is False:
                if instruct == 'pass':
                    container.append(False)
                    task_done.set()
                elif instruct == 'retry':
                    self.task_queue.put((url, retry_time - 1, task_done, container))
                elif instruct == 'wait':
                    self.wait_event.clear()
                    wait_timer = threading.Timer(wait_time, lambda: self.wait_event.set())
                    wait_timer.start()
                    self.task_queue.put((url, retry_time, task_done, container))
                elif instruct == 'all wait':
                    time.sleep(wait_time)
                    self.task_queue.put((url, retry_time, task_done, container))
                elif instruct == 'stop':
                    self.task_queue.put((url, retry_time, task_done, container))
                    break
            else:
                if instruct == 'wait':
                    self.wait_event.clear()
                    wait_timer = threading.Timer(wait_time, lambda: self.wait_event.set())
                    wait_timer.start()

                    container.append(content)
                    task_done.set()
                elif instruct == 'done':
                    container.append(content)
                    task_done.set()
