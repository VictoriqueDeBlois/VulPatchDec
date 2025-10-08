import multiprocessing as mp
import signal
from multiprocessing import Pool
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from hardcraft_feature import CVEFeatureExtractor, load_json


def init_worker():
    """初始化工作进程，设置信号处理"""
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


def process_single_row(args):
    """处理单行数据的函数"""
    index, row, nvd_json_path, timeout = args

    try:
        # 设置进程超时
        signal.alarm(timeout)

        cve = row['cve']
        commit_message = row['commit_message']
        commit_diff = row['commit_diff']
        nvd_json = nvd_json_path / f'{cve}.json'

        if not nvd_json.exists():
            return {'success': False, 'index': index, 'error': f'File not found: {cve}'}

        # 这里需要重新创建extractor实例，因为多进程间不能共享类实例
        extractor = CVEFeatureExtractor()
        nvd_data = load_json(nvd_json)
        features = extractor.extract_features(nvd_data, commit_message, commit_diff)

        new_row = row.to_dict()
        new_row.update(features)

        # 取消闹钟
        signal.alarm(0)

        return {'success': True, 'index': index, 'data': new_row}

    except Exception as e:
        signal.alarm(0)
        return {'success': False, 'index': index, 'error': str(e)}


def process_with_timeout_multiprocessing(df, nvd_json_path, num_processes=4, timeout=60):
    """
    使用多进程处理数据，支持超时控制

    Args:
        df: pandas DataFrame
        nvd_json_path: NVD JSON文件路径
        num_processes: 进程数量
        timeout: 每个任务的超时时间（秒）

    Returns:
        tuple: (new_data, failed_indices)
    """
    # 准备参数
    args_list = [(row['idx'], row, nvd_json_path, timeout) for index, row in df.iterrows()]

    new_data = []
    failed_indices = []

    # 创建进程池
    with Pool(processes=num_processes, initializer=init_worker) as pool:
        # 使用进度条
        with tqdm(total=len(df), desc="Processing CVEs") as pbar:
            # 异步提交所有任务
            results = []
            for args in args_list:
                result = pool.apply_async(process_single_row, (args,))
                results.append(result)

            # 收集结果
            for result in results:
                try:
                    # 等待结果，设置超时
                    res = result.get(timeout=timeout + 5)  # 给额外5秒缓冲

                    if res['success']:
                        new_data.append(res['data'])
                    else:
                        failed_indices.append(res['index'])
                        print(f"Failed at index {res['index']}: {res['error']}")

                except mp.TimeoutError:
                    # 超时处理
                    failed_indices.append(args_list[len(new_data) + len(failed_indices)][0])
                    print(f"Timeout at index {args_list[len(new_data) + len(failed_indices)][0]}")

                pbar.update(1)

    return new_data, failed_indices


def process_with_concurrent_futures(df, nvd_json_path, num_processes=4, timeout=60):
    """
    使用concurrent.futures的替代方案
    """
    from concurrent.futures import ProcessPoolExecutor, TimeoutError, as_completed

    def process_row_wrapper(args):
        return process_single_row(args)

    args_list = [(row['idx'], row, nvd_json_path, timeout) for index, row in df.iterrows()]

    new_data = []
    failed_indices = []

    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        # 提交所有任务
        future_to_index = {
            executor.submit(process_row_wrapper, args): args[0]
            for args in args_list
        }

        # 使用进度条
        with tqdm(total=len(df), desc="Processing CVEs") as pbar:
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    result = future.result(timeout=timeout)
                    if result['success']:
                        new_data.append(result['data'])
                    else:
                        failed_indices.append(result['index'])
                        print(f"Failed at index {result['index']}: {result['error']}")

                except TimeoutError:
                    failed_indices.append(index)
                    print(f"Timeout at index {index}")
                except Exception as e:
                    failed_indices.append(index)
                    print(f"Exception at index {index}: {str(e)}")

                pbar.update(1)

    return new_data, failed_indices


# 主函数修改版本
if __name__ == "__main__":
    nvd_json_path = Path('../VulnerCollector/data/CVE/DataSet-NVD/NVDItems')
    name = 'new_test_small'
    out_dir = Path('../data/handcraft_feature_cve')
    out_dir.mkdir(parents=True, exist_ok=True)
    # 加载数据
    # df = load_jsonl_to_pandas(f'./data/{name}.jsonl')

    df = pd.read_feather('../pythonProject/CVEKnowledgeMap/数据检查/new_test_small.feather')
    df = df.drop(columns=['branches', 'previous_tag', 'next_tag'])
    df = df.reset_index(drop=True)
    df['idx'] = df.index

    df.to_feather(out_dir / f'{name}_start.feather')

    # 配置参数
    num_processes = mp.cpu_count()  # 或者设置为固定值，如4
    timeout = 30  # 每个任务60秒超时

    print(f"Using {num_processes} processes with {timeout}s timeout per task")

    # 方法1：使用multiprocessing.Pool
    new_data, failed_indices = process_with_timeout_multiprocessing(
        df, nvd_json_path, num_processes, timeout
    )

    # 方法2：使用concurrent.futures（可选）
    # new_data, failed_indices = process_with_concurrent_futures(
    #     df, nvd_json_path, num_processes, timeout
    # )

    print(f"Successfully processed: {len(new_data)} items")
    print(f"Failed indices: {failed_indices}")

    # 保存结果
    if new_data:
        result_df = pd.DataFrame(new_data)
        result_df.to_feather(out_dir / f'{name}_processed.feather')
        result_path = out_dir / f'{name}_processed.feather'
        print(f"Results saved to {result_path}")

    # 保存失败的索引
    if failed_indices:
        failed_path = out_dir / f'{name}_failed_indices.txt'
        with open(failed_path, 'w') as f:
            for idx in failed_indices:
                f.write(f"{idx}\n")
        print(f"Failed indices saved to {failed_path}")


# 可选：重新处理失败的任务
def retry_failed_tasks(df, failed_indices, nvd_json_path, timeout=120):
    """重新处理失败的任务，使用更长的超时时间"""
    if not failed_indices:
        return []

    print(f"Retrying {len(failed_indices)} failed tasks...")
    failed_df = df.iloc[failed_indices]

    new_data, still_failed = process_with_timeout_multiprocessing(
        failed_df, nvd_json_path, num_processes=2, timeout=timeout
    )

    return new_data, still_failed