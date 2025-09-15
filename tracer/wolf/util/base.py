import logging
import multiprocessing
import os
import random
import threading
from functools import wraps
from multiprocessing.pool import ThreadPool


class Base:
    def __init__(self, logger=None, log_path=None):
        self._name = None
        self._log_path = None
        self._base_path = None

        if logger is not None:
            self._logger = logging.getLogger(logger)
        else:
            if log_path is not None:
                self._log_path = log_path
            self._create_logger()

    def _create_logger(self):
        dirname = os.path.dirname(self.log_path)
        os.makedirs(dirname, exist_ok=True)
        if self.name in logging.Logger.manager.loggerDict:
            self._logger = logging.getLogger(self.name)
            return
        self._logger = logging.getLogger(self.name)
        self._logger.setLevel(logging.INFO)
        logger_handler = logging.FileHandler(self.log_path, encoding='utf-8')
        logger_handler.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s: %(message)s")
        logger_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)

        for h in self._logger.handlers:
            self._logger.removeHandler(h)
        self._logger.addHandler(logger_handler)
        self._logger.addHandler(console_handler)

    @property
    def name(self):
        if self._name is None:
            self._name = type(self).__name__
        return self._name

    @property
    def log_path(self):
        if self._log_path is not None:
            return self._log_path
        return os.path.join(self.base_path, f'./log/{self.name}.log')

    @property
    def base_path(self):
        if self._base_path is None:
            path, _ = os.path.split(__file__)
            while '__init__.py' in os.listdir(path):
                path, _ = os.path.split(path)
            self._base_path = path
        return self._base_path


def range_start_at(size, start=None):
    if start is None:
        start = random.Random().randint(0, size - 1)
    else:
        start = start % size
    for _ in range(size):
        yield start
        start = (start + 1) % size


def limiter(timeout):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            pool = ThreadPool(processes=1)
            future = pool.apply_async(func, args=args, kwds=kwargs)
            try:
                result = future.get(timeout)
            except multiprocessing.context.TimeoutError as e:
                pool.terminate()
                raise TimeoutError(f"Function execution timed out after {timeout} seconds")
            return result

        return wrapper

    return decorator


def limiter1(timeout):
    def timer():
        raise TimeoutError(f"Function execution timed out after {timeout} seconds")

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                wait_timer = threading.Timer(timeout, timer)
                wait_timer.start()
                result = func(*args, **kwargs)
            except TimeoutError as e:
                raise e
            return result

        return wrapper

    return decorator
