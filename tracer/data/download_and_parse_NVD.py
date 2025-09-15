#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NVD CVE 数据下载和处理脚本
支持下载NVD JSON数据源，自动解压并将每个CVE拆分为单独的JSON文件
"""

import gzip
import hashlib
import json
import os
import zipfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import requests
from tqdm.std import tqdm

from vulnerability_analysis import config
from wolf.util.util import setup_logging


class NVDDownloader:
    """NVD数据下载器"""
    NVD_dataset_path = config.NVD_DATASET_DIR
    NVD_dataset_items_dir = config.NVD_DATASET_ITEMS_DIR
    NVD_CPErange_items_dir = config.NVD_CPERANGE_ITEMS_DIR

    def __init__(self):
        self.logger = setup_logging('download_and_parse_NVD')
        self.base_dir = Path(NVDDownloader.NVD_dataset_path)
        self.base_dir.mkdir(exist_ok=True, parents=True)

        self.version = '2.0'

        self.base_url = f"https://nvd.nist.gov/feeds/json/cve/{self.version}/"

        # 创建子目录
        self.downloads_dir = self.base_dir / "downloads"
        self.extracted_dir = self.base_dir / "extracted"
        self.individual_cves_dir = Path(NVDDownloader.NVD_dataset_items_dir)

        for dir_path in [self.downloads_dir, self.extracted_dir, self.individual_cves_dir]:
            dir_path.mkdir(exist_ok=True)

    def check_meta_file(self, file_prefix: str) -> dict:
        """检查META文件获取最新信息"""
        file_prefix = Path(file_prefix).stem
        meta_url = f"{self.base_url}{file_prefix}.meta"
        try:
            response = requests.get(meta_url, timeout=30)
            response.raise_for_status()

            meta_info = {}
            for line in response.text.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    meta_info[key] = value

            return meta_info
        except Exception as e:
            self.logger.warning(f"无法获取META文件 {meta_url}: {e}")
            return {}

    def download_file(self, url: str, local_path: Path, expected_sha256: str = None) -> bool:
        """下载文件并验证"""
        try:
            self.logger.info(f"开始下载: {url}")

            response = requests.get(url, stream=True, timeout=60)
            response.raise_for_status()

            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            extracted_path = self.extract_file(local_path)

            # 验证下载的文件
            if expected_sha256 and not self.verify_file_hash(extracted_path, expected_sha256):
                self.logger.error(f"文件校验失败: {local_path}")
                local_path.unlink()  # 删除无效文件
                return False

            self.logger.info(f"下载完成: {local_path}")
            return True

        except Exception as e:
            self.logger.error(f"下载失败 {url}: {e}")
            return False

    def verify_file_hash(self, file_path: Path, expected_sha256: str) -> bool:
        """验证文件SHA256哈希值"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)

            return sha256_hash.hexdigest().lower() == expected_sha256.lower()
        except Exception as e:
            self.logger.error(f"文件校验出错: {e}")
            return False

    def extract_file(self, archive_path: Path) -> Optional[Path]:
        """解压文件 (支持.gz和.zip格式)"""
        output_path = self.extracted_dir / archive_path.stem
        if output_path.exists():
            return output_path
        try:
            if archive_path.suffix == '.gz':
                with gzip.open(archive_path, 'rb') as f_in:
                    with open(output_path, 'wb') as f_out:
                        f_out.write(f_in.read())

            elif archive_path.suffix == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    extracted_files = zip_ref.namelist()
                    zip_ref.extractall(self.extracted_dir)
                    json_files = [f for f in extracted_files if f.endswith('.json')]
                    if not json_files:
                        raise ValueError("ZIP文件中没有找到JSON文件")
            else:
                raise ValueError(f"不支持的文件格式: {archive_path.suffix}")

            self.logger.info(f"解压完成: {output_path}")
            return output_path

        except Exception as e:
            self.logger.error(f"解压失败 {archive_path}: {e}")
            return None

    def split_cves(self, json_file_path: Path) -> int:
        """将大JSON文件拆分为单独的CVE文件"""
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            cve_items = data.get('vulnerabilities', [])
            if not cve_items:
                self.logger.warning(f"在文件中没有找到CVE_Items: {json_file_path}")
                return 0

            json_year = json_file_path.stem[-4:]

            count = 0
            for item in tqdm(cve_items, desc=json_year):
                cve_id = item.get('cve', {}).get('id', {})
                if not cve_id:
                    self.logger.warning("找到一个没有ID的CVE项目，跳过")
                    continue

                # 创建年份目录
                year = cve_id.split('-')[1] if len(cve_id.split('-')) > 1 else 'unknown'
                year_dir = self.individual_cves_dir / year
                year_dir.mkdir(exist_ok=True)

                # 保存单个CVE文件
                cve_file_path = year_dir / f"{cve_id}.json"
                with open(cve_file_path, 'w', encoding='utf-8') as cve_file:
                    json.dump(item, cve_file, indent=2, ensure_ascii=False)

                count += 1

            self.logger.info(f"成功拆分 {count} 个CVE文件从 {json_file_path}")
            return count

        except Exception as e:
            self.logger.error(f"拆分CVE失败 {json_file_path}: {e}")
            return 0

    def download_and_process_year(self, year: int, format_type: str = "zip") -> bool:
        """下载并处理指定年份的数据"""
        file_prefix = f"nvdcve-{self.version}-{year}.json"

        # 检查META文件
        meta_info = self.check_meta_file(file_prefix)
        expected_sha256 = meta_info.get('sha256', '').strip()

        # 下载压缩文件
        archive_url = f"{self.base_url}{file_prefix}.{format_type}"
        archive_path = self.downloads_dir / f"{file_prefix}.{format_type}"

        have_to_download = True
        # 检查文件是否已存在且有效
        extracted_path = self.extracted_dir / archive_path.stem
        if extracted_path and extracted_path.exists() and expected_sha256:
            if self.verify_file_hash(extracted_path, expected_sha256):
                self.logger.info(f"文件已存在且校验通过: {extracted_path}")
                have_to_download = False
            else:
                self.logger.error(f"文件已存在但校验失败: {extracted_path}")
                archive_path.unlink()  # 删除无效文件
                extracted_path.unlink()

        if have_to_download and not self.download_file(archive_url, archive_path, expected_sha256):
            return False

        extracted_path = self.extract_file(archive_path)
        if not extracted_path.exists():
            return False

        if self.verify_file_hash(extracted_path, expected_sha256):
            self.logger.info(f"文件校验通过: {extracted_path}")
        else:
            self.logger.error(f"文件校验失败: {extracted_path}")
            archive_path.unlink()  # 删除无效文件
            extracted_path.unlink()
            return False

        # 拆分CVE
        cve_count = self.split_cves(extracted_path)
        self.logger.info(f"{year}年数据处理完成，共处理 {cve_count} 个CVE")

        return True

    def download_recent_modified(self, format_type: str = "zip") -> bool:
        """下载recent和modified数据"""
        success = True

        for feed_type in ['recent', 'modified']:
            file_prefix = f"nvdcve-{self.version}-{feed_type}.json"

            # 检查META文件
            meta_info = self.check_meta_file(file_prefix)
            expected_sha256 = meta_info.get('sha256', '').strip()

            # 下载文件
            archive_url = f"{self.base_url}{file_prefix}.{format_type}"
            archive_path = self.downloads_dir / f"{file_prefix}.{format_type}"

            if self.download_file(archive_url, archive_path, expected_sha256):
                # 解压文件
                extracted_path = self.extract_file(archive_path)
                if extracted_path:
                    # 拆分CVE
                    cve_count = self.split_cves(extracted_path)
                    self.logger.info(f"{feed_type}数据处理完成，共处理 {cve_count} 个CVE")
                else:
                    success = False
            else:
                success = False

        return success

    def get_available_years(self) -> List[int]:
        """获取可用的年份列表"""
        # NVD从2002年开始有数据，到当前年份
        current_year = datetime.now().year
        return list(range(2002, current_year + 1))

    def cleanup_downloads(self):
        """清理下载的压缩文件（可选）"""
        try:
            for file_path in self.downloads_dir.glob("*.zip"):
                file_path.unlink()
            for file_path in self.downloads_dir.glob("*.gz"):
                file_path.unlink()
            self.logger.info("清理下载文件完成")
        except Exception as e:
            self.logger.error(f"清理文件失败: {e}")

if __name__ == "__main__":
    os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7890'
    os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7890'
    downloader = NVDDownloader()
    years = downloader.get_available_years()
    for i, year in enumerate(years):
        print(f'处理进度: {i + 1}/{len(years)}')
        downloader.download_and_process_year(year, 'zip')
