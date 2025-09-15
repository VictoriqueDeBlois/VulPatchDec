import json
import pickle
import os
import gzip
from typing import Any, Optional

def save_pkl(data: Any, filepath: str, compress: bool = False, protocol: Optional[int] = None) -> bool:
    """
    保存数据到pkl文件

    Args:
        data: 要保存的数据（任何可pickle的Python对象）
        filepath: 保存文件的路径
        compress: 是否压缩文件（使用gzip）
        protocol: pickle协议版本，None表示使用最新版本

    Returns:
        bool: 保存成功返回True，失败返回False

    Example:
        >>> data = {'key': 'value', 'numbers': [1, 2, 3]}
        >>> save_pkl(data, 'data.pkl')
        True
        >>> save_pkl(data, 'data.pkl.gz', compress=True)
        True
    """
    try:
        # 创建目录（如果不存在）
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # 根据是否压缩选择不同的打开方式
        if compress:
            with gzip.open(filepath, 'wb') as f:
                pickle.dump(data, f, protocol=protocol)
        else:
            with open(filepath, 'wb') as f:
                pickle.dump(data, f, protocol=protocol)
        return True

    except Exception as e:
        print(e)
        return False


def load_pkl(filepath: str, default: Any = None) -> Any:
    """
    从pkl文件加载数据

    Args:
        filepath: 文件路径
        default: 如果文件不存在或加载失败时返回的默认值

    Returns:
        加载的数据，如果失败则返回default值

    Example:
        >>> data = load_pkl('data.pkl')
        >>> data = load_pkl('data.pkl', default={})  # 失败时返回空字典
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(filepath):
            if default is not None:
                return default
            else:
                raise FileNotFoundError(f"文件不存在: {filepath}")

        # 根据文件扩展名判断是否为压缩文件
        is_compressed = filepath.endswith('.gz')

        if is_compressed:
            with gzip.open(filepath, 'rb') as f:
                data = pickle.load(f)
        else:
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
        return data

    except Exception as e:
        if default is not None:
            return default
        else:
            raise


def load_json(path):
    with open(path, 'r', encoding='utf-8') as fp:
        data = json.load(fp)
    return data


def save_json(data, path):
    with open(path, 'w', encoding='utf-8') as fp:
        json.dump(data, fp, indent=4)