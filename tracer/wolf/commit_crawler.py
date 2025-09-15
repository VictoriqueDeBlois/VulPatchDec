import os.path

import pandas as pd

from wolf.function_searcher import FunctionSearcher, Antlr4Searcher
from wolf.util import Base
from wolf.util.crawler import GitHubCrawlerPool
from wolf.util.normal_crawler import BaseCrawlerPool


class BaseCommitCrawler(Base):
    def __init__(self, logger=None, log_path=None):
        super().__init__(logger=logger, log_path=log_path)
        self._raw_code_path = None
        self._diff_save_path = None
        self.vdb = pd.read_csv(os.path.join(self.base_path, './vdb.csv'))
        self.http_pool = BaseCrawlerPool()
        self.searcher = Antlr4Searcher(logger=logger, log_path=log_path)

    def process_url(self, url):
        raise NotImplementedError

    def get_commit_message(self, url):
        raise NotImplementedError

    def get_diff_text(self, url):
        raise NotImplementedError

    def get_code_file_url(self, url, path):
        raise NotImplementedError

    @property
    def diff_path(self):
        name = self.name
        pos = name.find('Commit')
        name = name[:pos]
        name = name.lower()
        if self._diff_save_path is None:
            diff_save_path = os.path.join(self.base_path, f'./{name}_diff')
            os.makedirs(diff_save_path, exist_ok=True)
            self._diff_save_path = diff_save_path
        return self._diff_save_path

    @property
    def raw_code_path(self):
        if self._raw_code_path is None:
            path = os.path.join(self.diff_path, 'raw_code')
            os.makedirs(path, exist_ok=True)
            self._raw_code_path = path
        return self._raw_code_path

    def get_raw_code_file(self, url, path):
        raw_url = self.get_code_file_url(url, path)
        file_path = self.get_code_file_path(url, path, 'b')
        return self.load_or_download(raw_url, file_path)

    def get_code_file_path(self, url, path, ver):
        owner, repo, sha = self.process_url(url)
        file_path = os.path.join(self.raw_code_path, f'{owner}/{repo}/{sha}{path}')
        path, ext = os.path.splitext(file_path)
        if ver == 'a':
            file_path = f'{path}_a{ext}'
        else:
            file_path = f'{path}_b{ext}'
        return file_path

    def diff_save_path(self, owner, repo, sha):
        return os.path.join(self.base_path, self.diff_path, f'{owner}_{repo}_{sha}.diff')

    def load_or_download(self, url, path):
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as fp:
                text = fp.read()
        else:
            text = self.http_pool.get(url)
            if text is False:
                return None
            sub_path, file = os.path.split(path)
            os.makedirs(sub_path, exist_ok=True)
            with open(path, 'w', encoding='utf-8') as fp:
                fp.write(text)
        return text

    @staticmethod
    def recover_code_by_diff(code_file, blocks):
        add_line = []
        del_line = []
        for b in blocks:
            for a in b['add']:
                add_line.append(a)
            for d in b['del']:
                del_line.append(d)

        code_file = code_file.splitlines()
        for a in add_line[::-1]:
            code_file.pop(a[0] - 1)
        for d in del_line:
            code_file.insert(d[0] - 1, d[1])
        return '\n'.join(code_file)

    def get_commit(self, url):
        parts = self.process_url(url)
        if parts is None:
            self._logger.error("url: %s url解析错误，可能不是commit链接", url)
            return None

        owner, repo, sha = parts
        commit_message = self.get_commit_message(url)
        if commit_message is None:
            commit_message = ""
        diff_text = self.get_diff_text(url)
        if diff_text is None:
            self._logger.error("url: %s 访问获取diff出错", url)
            return None

        diff_lines = diff_text.splitlines()
        info = {}
        file = None
        old_line = 0
        new_line = 0
        block = None
        for line in diff_lines:
            if line.startswith('diff'):
                # 解析文件差异的起始行
                # 在这里可以提取文件名、路径等信息
                file = line.split()[-1][1:]
                info[file] = {'blocks': []}
            elif line.startswith('---') or line.startswith('+++'):
                # 解析文件名行
                # 在这里可以提取旧文件名和新文件名
                file_name = line.split()[-1][1:]
                if '---' == line[0:3]:
                    info[file]['old_file'] = file_name
                else:
                    info[file]['new_file'] = file_name
            elif line.startswith('@@'):
                # 解析差异块的起始行
                # 在这里可以提取差异块的位置信息
                line_info = line.split('@@')[1].strip()
                old, new = line_info.split(' ')
                old_line = int(old.split(',')[0][1:])
                new_line = int(new.split(',')[0][1:])
                block_info = (line.split('@@')[-1].strip(), old_line, new_line)
                block = {'info': block_info, 'add': [], 'del': []}
                info[file]['blocks'].append(block)
            elif line.startswith('-'):
                # 解析删除的行
                block['del'].append((old_line, line[1:]))
                old_line += 1
            elif line.startswith('+'):
                # 解析添加的行
                block['add'].append((new_line, line[1:]))
                new_line += 1
            elif line.startswith(' '):
                # 解析未更改的行
                new_line += 1
                old_line += 1
            else:
                # 其他情况的行，根据需要进行处理
                pass

        commit_info = {'url': url,
                       'owner': owner,
                       'repo': repo,
                       'commit_message': commit_message,
                       'files': []}
        langs = set()
        # commit中的每个文件搜索函数
        for path, diff in info.items():
            lang = FunctionSearcher.get_language(path)
            if lang == 'Unknown':
                continue
            if lang.lower() not in {'c',
                                    'go',
                                    'python',
                                    'cpp',
                                    'java',
                                    'javascript'}:
                continue
            langs.add(lang)
            code_file = self.get_raw_code_file(url, path)
            if code_file is None:
                self._logger.error("获取不到%s代码，url：%s", path, self.get_code_file_url(url, path))
                continue
            a_code_file = self.recover_code_by_diff(code_file, diff['blocks'])
            b_code_file = code_file

            a_code_file_path = self.get_code_file_path(url, path, 'a')
            b_code_file_path = self.get_code_file_path(url, path, 'b')

            with open(a_code_file_path, 'w', encoding='utf-8') as fp:
                fp.write(a_code_file)

            file_info = {'path': path,
                         'functions': []}

            add_lines = []
            del_lines = []
            for block in diff['blocks']:
                add_lines += list(map(lambda x: x[0], block['add']))
                del_lines += list(map(lambda x: x[0], block['del']))

            b_funcs = self.searcher.search_function_by_line(b_code_file_path, add_lines)
            a_funcs = self.searcher.search_function_by_line(a_code_file_path, del_lines)

            if a_funcs is None or b_funcs is None:
                self._logger.error("%s 的代码无法解析。路径：%s；语言：%s", url, path, lang)
                continue

            b_funcs = {f.func_decl: f for f in b_funcs}
            a_funcs = {f.func_decl: f for f in a_funcs}

            self.map_funcs(self.searcher, a_funcs, b_funcs, a_code_file_path, b_code_file_path)

            for decl, b_func in b_funcs.items():
                a_func = a_funcs[decl]
                change_lines = []
                if b_func is not None:
                    change_lines = self.in_line_range(add_lines, b_func.start_line, b_func.end_line)
                if len(change_lines) == 0:
                    if a_func is not None:
                        change_lines = self.in_line_range(del_lines, a_func.start_line, a_func.end_line)
                    else:
                        self._logger.error("不能理解的错误, 在%s", url)
                        continue
                func_info = {'line': change_lines,
                             'func_name': decl,
                             'a_func': a_code_file[a_func.start_index: a_func.end_index] if a_func is not None else "",
                             'b_func': b_code_file[b_func.start_index: b_func.end_index] if b_func is not None else ""
                             }
                file_info['functions'].append(func_info)
            commit_info['files'].append(file_info)

        commit_info['langs'] = list(langs)
        return commit_info

    @staticmethod
    def map_funcs(searcher, a_set: dict, b_set: dict, a_file, b_file):
        remain = set(a_set.keys()) - set(b_set.keys())
        for i in remain:
            method = searcher.search_function_by_decl(b_file, i)
            b_set[i] = method

        remain = set(b_set.keys()) - set(a_set.keys())
        for i in remain:
            method = searcher.search_function_by_decl(a_file, i)
            a_set[i] = method

    @staticmethod
    def in_line_range(lines, start, end):
        return list(filter(lambda l: start <= l <= end, lines))


class GitHubCommit(BaseCommitCrawler):
    def __init__(self, logger=None, log_path=None):
        super().__init__(logger=logger, log_path=log_path)

    def process_url(self, url):
        parts = url.split('/')
        try:
            owner = parts[3]
            repo = parts[4]
            sha = parts[-1]
            return owner, repo, sha
        except IndexError:
            return None

    def get_commit_message(self, url):
        owner, repo, sha = self.process_url(url)
        pool = GitHubCrawlerPool()
        commit_data = pool.get(f'https://api.github.com/repos/{owner}/{repo}/commits/{sha}')
        if commit_data is False:
            return None
        return commit_data['commit']['message']

    def get_code_file_url(self, url, path):
        owner, repo, sha = self.process_url(url)
        raw_url = f'https://raw.githubusercontent.com/{owner}/{repo}/{sha}{path}'
        return raw_url

    def get_diff_text(self, url):
        owner, repo, sha = self.process_url(url)
        diff_file = self.diff_save_path(owner, repo, sha)
        return self.load_or_download(url + '.diff', diff_file)
