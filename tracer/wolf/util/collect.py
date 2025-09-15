import os
import re

from .base import Base


class Collect(Base):
    def get_cve_file(self, cve, out_path):
        os.makedirs(out_path, exist_ok=True)
        m = re.match(r'CVE-(\d+)-(\d+)', cve)
        if m is None:
            print(f'错误CVE: {cve}')
            return
        year = m.group(1)
        src_file = os.path.join(self.base_path, f'change_{year}', f'{cve}.json')
        dst_file = os.path.join(out_path, f'{cve}.json')
        if os.path.exists(dst_file):
            print(f'{cve}存在')
            return
        os.link(src_file, os.path.join(out_path, f'{cve}.json'))

    def get_cve_files(self, cve_list, out_path):
        list(map(lambda cve: self.get_cve_file(cve, out_path), cve_list))


if __name__ == '__main__':
    collect = Collect()
    log_file = os.path.join(collect.base_path, 'cvss', 'cvss3_reason.log')
    collect_path = os.path.join(collect.base_path, 'cvss', 'cvss3_reason_log_cve')
    with open(log_file, 'r') as fp:
        for line in fp:
            m = re.search(r'CVE-\d+-\d+', line)
            cve = m.group()
            collect.get_cve_file(cve, collect_path)
