import os
import re
import subprocess

from wolf.util import Base


class FunctionSearcher(Base):
    def __init__(self):
        super().__init__()

    @staticmethod
    def forward_search(pattern, text, start_pos, end_pos):
        # 前向搜索匹配的内容
        match = re.search(pattern, text[start_pos:end_pos])
        if match:
            return match.group(0)
        return None

    def get_function_with_brace(self, code_file, start_line, end_line):
        start = code_file.find(start_line)
        end = self.get_line_position(code_file, end_line)
        if code_file.find('{', start) > end:
            return -1, -1

        a, b = self.find_function_closing_brace(code_file, start)
        while b != -1 and b < end:
            a, b = self.find_function_closing_brace(code_file, b + 1)
        return a, b

    @staticmethod
    def get_line_position(text, line_number):
        lines = text.split('\n')
        if line_number <= len(lines):
            line_start_pos = sum(len(lines[i]) + 1 for i in range(line_number - 1))
            return line_start_pos
        return -1

    @staticmethod
    def find_next_brace(code, start_index):
        match = re.search(r'[{}]', code[start_index:])
        if match:
            return match.start() + start_index
        return -1

    def find_matching_brace(self, code, start_index):
        stack = 1
        i = start_index
        while stack >= 1:
            i = self.find_next_brace(code, i + 1)
            if i == -1:
                break
            if code[i] == '{':
                stack += 1
            else:
                stack -= 1
        if stack != 0:
            return -1
        return i

    def find_function_closing_brace(self, code, start_index):
        if start_index == -1:
            return -1, -1
        brace_index = code.find('{', start_index)
        if brace_index == -1:
            return -1, -1
        closing_brace_index = self.find_matching_brace(code, brace_index)
        return brace_index, closing_brace_index

    @staticmethod
    def get_language(file_name):
        extension = file_name.split('.')[-1].lower()

        if extension in ['c', 'h']:
            return 'C'
        if extension in ['cpp', 'cxx', 'cc', 'c++', 'h++', 'hpp', 'hxx', 'inl', 'ii', 'ixx']:
            return 'Cpp'
        elif extension == 'java':
            return 'Java'
        elif extension == 'py':
            return 'Python'
        elif extension == 'rb':
            return 'Ruby'
        elif extension == 'js':
            return 'JavaScript'
        elif extension == 'php':
            return 'PHP'
        elif extension == 'html' or extension == 'htm':
            return 'HTML'
        elif extension == 'css':
            return 'CSS'
        elif extension == 'sql':
            return 'SQL'
        elif extension == 'swift':
            return 'Swift'
        elif extension == 'go':
            return 'Go'
        elif extension == 'pl':
            return 'Perl'
        elif extension == 'lua':
            return 'Lua'
        elif extension == 'r' or extension == 'R':
            return 'R'
        elif extension == 'matlab':
            return 'MATLAB'
        elif extension == 'vb':
            return 'Visual Basic'
        else:
            return 'Unknown'

    @staticmethod
    def line_pos(lines, line):
        return sum(map(len, lines[:line - 1])) + line - 1

    def search_modified_functions(self, block_change, tmp_code_file, tmp_code_file_lines, is_comment, is_func,
                                  modified_functions):
        for line, line_code in block_change:
            modified_line = line
            modified_pos = self.line_pos(tmp_code_file_lines, modified_line)
            if is_comment(line_code):
                continue

            while line > 0:
                if not is_func(tmp_code_file_lines[line], tmp_code_file_lines[line + 1]):
                    line -= 1
                    continue
                start_pos = self.line_pos(tmp_code_file_lines, line)
                start, end = self.find_function_closing_brace(tmp_code_file, start_pos)
                if start == -1 or end == -1:
                    self._logger.error()
                    # todo
                if modified_pos > end:
                    line -= 1
                    continue
                else:
                    func_pos = start_pos
                    func_name = tmp_code_file[func_pos:start].strip()
                    func = tmp_code_file[func_pos:end + 1].strip()
                    modified_functions[func_name] = func

    @staticmethod
    def search_functions(pattern, code_file):
        match = re.search(pattern, code_file)
        print(match)
        pass

    @staticmethod
    def get_lang_function_pattern(lang):
        if lang == 'C/C++':
            return re.compile(r'\s*.+\s+\w+\s*\((?:.+\s+.+)?(?:,\s+.+\s+.+)*\)\s*{')
        elif lang == 'Java':
            return re.compile(r'')
        elif lang == 'Go':
            return re.compile(r'')
        elif lang == 'JavaScript':
            return re.compile(r'')
        elif lang == 'Python':
            return re.compile(r'')
        else:
            return

    @staticmethod
    def get_lang_comment(lang):
        if lang == 'C/C++':
            return re.compile(r'\s*((//)|(/\*)|\*).*')
        elif lang == 'Java':
            return re.compile(r'')
        elif lang == 'Go':
            return re.compile(r'')
        elif lang == 'JavaScript':
            return re.compile(r'')
        elif lang == 'Python':
            return re.compile(r'')
        else:
            return

    def is_comment_func(self, lang):
        pattern = self.get_lang_comment(lang)

        def func(s):
            if pattern.match(s):
                return True
            return False

        return func

    def is_function_func(self, lang):
        pattern = self.get_lang_function_pattern(lang)

        def func(s1, s2):
            if pattern.match(s1):
                return True
            elif pattern.match(s1 + '\n' + s2):
                return True
            else:
                return False

        return func


class Antlr4Searcher(Base):
    def __init__(self, logger=None, log_path=None):
        super().__init__(logger=logger, log_path=log_path)
        self.java_path = '/home/xuhaoran/program/jdk-20.0.2/bin/java'
        self.jar_path = os.path.join(self.base_path, 'java', 'antlrparser-1.0-jar-with-dependencies.jar')

    def call_java_method(self, lang, filename, *args):
        classname = self._select_searcher(lang)
        java_command = [
            self.java_path,
            "-cp",
            self.jar_path,  # 替换为JAR文件的实际路径
            classname,      # 替换为您要调用的类的完整路径
            filename
        ] + [str(arg) for arg in args]
        try:
            result = subprocess.check_output(java_command, stderr=subprocess.STDOUT, text=True)
            result = result.strip()
            results = []
            for line in result.splitlines():
                line = line.strip()
                m = re.match(r'(\d+), (\d+), (\d+), (\d+), (.+)', line)
                if m is None:
                    continue
                fragment = MethodFragment(*m.groups())
                results.append(fragment)
            return results
        except subprocess.CalledProcessError as e:
            self._logger.error(f"Error while calling Java code: {e}")
            return None

    def search_function_by_line(self, filename, lines):
        if len(lines) == 0:
            return []
        lang = FunctionSearcher.get_language(filename)
        return self.call_java_method(lang, filename, *lines)

    def search_function_by_decl(self, filename, decl):
        lang = FunctionSearcher.get_language(filename)
        results = self.call_java_method(lang, filename, decl)
        if results is None or len(results) == 0:
            return None
        return results[0]

    @staticmethod
    def _select_searcher(lang):
        lang = lang.lower()
        lang_map = {
            'c': 'CSearcher',
            'go': 'GolangSearcher',
            'python': 'PythonSearcher',
            'cpp': 'CppSearcher',
            'java': 'JavaSearcher',
            'javascript': 'JavascriptSearcher'
        }
        if lang not in lang_map:
            raise KeyError('没有对应的语言搜索类')
        classname = f'com.wolf.antlr.{lang_map[lang]}'
        return classname


class MethodFragment:
    def __init__(self, start_index, end_index,
                 start_line, end_line,
                 func_decl):
        self.func_decl = func_decl
        self.end_line = int(end_line)
        self.start_line = int(start_line)
        self.end_index = int(end_index)
        self.start_index = int(start_index)

    def __str__(self):
        return f'{self.func_decl}, {self.start_index}, {self.end_index}, {self.start_line}, {self.end_line}'


if __name__ == '__main__':
    searcher = Antlr4Searcher()
    code_file = os.path.join(searcher.base_path, './github_diff/Files.java')
    out = searcher.search_function_by_line(code_file, [286, 301])
    for i in out:
        print(i)
    with open(code_file, 'r', encoding='utf-8') as fp:
        buffer = fp.read()
    for f in out:
        print(buffer[f.start_index: f.end_index])
        print()

    for i in out:
        find = searcher.search_function_by_decl(code_file, i.func_decl)
        print(find)
        print(buffer[find.start_index: find.end_index])
