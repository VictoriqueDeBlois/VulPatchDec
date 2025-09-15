import gc
from pathlib import Path

import pandas as pd
import torch
import numpy as np
from torch.utils.data import Dataset
from tqdm import tqdm
from transformers import AutoTokenizer
'''
concat the msg and diff tokens to train
'''
class CVEDataset(Dataset):
    def __init__(self, file_name):
        self.df = pd.read_csv(file_name)
        self.cve = self.df['cve']
        self.desc_tokens = self.df['desc_token']
        # Combine msg and diff tokens with a space separator
        self.msg_diff_tokens = self.df['msg_token'] + " " + self.df['diff_token']
        self.labels = self.df['label']
        self.tokenizer = AutoTokenizer.from_pretrained("microsoft/codereviewer")
        
    def __getitem__(self, index):
        desc = self.desc_tokens[index] if isinstance(self.desc_tokens[index], str) else ''
        desc_encoding = self.tokenizer.encode_plus(
            desc,
            add_special_tokens=True,
            max_length=128,
            return_token_type_ids=False,
            padding='max_length',
            return_attention_mask=True,
            return_tensors='pt',
            truncation=True
        )
        
        msg_diff = self.msg_diff_tokens[index] if isinstance(self.msg_diff_tokens[index], str) else ''
        msg_diff_encoding = self.tokenizer.encode_plus(
            msg_diff,
            add_special_tokens=True,
            max_length=512,
            return_token_type_ids=False,
            padding='max_length',
            return_attention_mask=True,
            return_tensors='pt',
            truncation=True
        )

        return {
            'input_ids_desc': desc_encoding['input_ids'].flatten(),
            'attention_mask_desc': desc_encoding['attention_mask'].flatten(),
            'input_ids_msg_diff': msg_diff_encoding['input_ids'].flatten(),
            'attention_mask_msg_diff': msg_diff_encoding['attention_mask'].flatten(),
            'label': torch.tensor(self.labels[index], dtype=torch.float),
            'cve': self.cve[index]
        }

    def __len__(self):
        return len(self.df)


class PreCVEDataset(Dataset):
    def __init__(self):
        pre_dir = Path('./preprocess')

        self.input_ids_desc = torch.load(pre_dir / 'desc_encode' /'input_ids_desc.pt')
        self.attention_mask_desc = torch.load(pre_dir / 'desc_encode' /'attention_mask_desc.pt')
        self.desc_tokens_codes = np.load(pre_dir / 'desc_encode' / 'desc_tokens_codes.npy')

        self.cve_codes = np.load(pre_dir / 'cve' / 'cve_codes.npy')
        with open(pre_dir / 'cve' / 'cve.txt', 'r', encoding='utf-8') as f:
            self.cve = f.readlines()

        self.labels = np.load(pre_dir / 'labels.npy')

        self.input_ids_msg_diff = torch.load(pre_dir / 'msg_diff_encode' / 'input_ids.pt')
        self.attention_mask_msg_diff = torch.load(pre_dir / 'msg_diff_encode' / 'attention_mask.pt')

    def __getitem__(self, index):
        desc_code = self.desc_tokens_codes[index]
        cve_code = self.cve_codes[index]
        return {
            'input_ids_desc': self.input_ids_desc[desc_code],
            'attention_mask_desc': self.attention_mask_desc[desc_code],
            'input_ids_msg_diff': self.input_ids_msg_diff[index],
            'attention_mask_msg_diff': self.attention_mask_msg_diff[index],
            'label': self.labels[index],
            'cve': self.cve[cve_code]
        }

    def __len__(self):
        return len(self.labels)


def batch_encode_texts(save_dir, texts, tokenizer, batch_size=16):
    """分批处理大量文本"""
    save_dir = Path(save_dir) /  f'encode_pt_{batch_size}'
    save_dir.mkdir(parents=True, exist_ok=True)

    for i in tqdm(range(0, len(texts), batch_size), desc="Encoding batches"):
        # 获取当前批次
        batch_num = i // batch_size

        if (save_dir / f'input_ids_{batch_num}.pt').exists() and (save_dir / f'attention_mask_{batch_num}.pt').exists():
            continue

        batch = texts[i:i+batch_size]

        # 批量encode
        encoded = tokenizer(
            batch,
            add_special_tokens=True,
            max_length=512,
            return_token_type_ids=False,
            padding='max_length',
            return_attention_mask=True,
            return_tensors='pt',
            truncation=True
        )
        input_ids = encoded['input_ids']
        attention_mask = encoded['attention_mask']

        torch.save(input_ids, save_dir / f'input_ids_{batch_num}.pt')
        torch.save(attention_mask, save_dir / f'attention_mask_{batch_num}.pt')

        del encoded
        del input_ids
        del attention_mask
        gc.collect()


def merge_pt(save_dir):
    input_ids = []
    attention_mask = []
    batch_count = len(list(save_dir.glob('*.pt'))) // 2
    for num in tqdm(list(range(batch_count)), desc="Loading batches input"):
        input_ids_file = save_dir / f'input_ids_{num}.pt'
        input_id_batch = torch.load(input_ids_file)
        input_ids.append(input_id_batch)
        attention_mask_file = save_dir / f'attention_mask_{num}.pt'
        attention_mask_batch = torch.load(attention_mask_file)
        attention_mask.append(attention_mask_batch)
    input_ids = torch.cat(input_ids, dim=0)
    attention_mask = torch.cat(attention_mask, dim=0)
    home_dir = save_dir.parent
    torch.save(input_ids, home_dir / 'input_ids.pt')
    torch.save(attention_mask, home_dir / 'attention_mask.pt')

def preprocess(file_name, encode_batch_size):
    file_name = Path(file_name)
    name = file_name.stem
    ext = file_name.suffix
    if ext == '.feather':
        df = pd.read_feather(file_name)
        df = df.rename(columns={'commit_message': 'commit_mess', 'cve_description': 'desc_cve', 'commit_diff': 'diff_ori'})
    elif ext == '.jsonl':
        df = pd.read_json(file_name, lines=True)
    else:
        raise TypeError(f'不知道的文件{file_name}')

    cve_code, unique_cve = pd.factorize(df['cve'])
    unique_cve = list(unique_cve)
    desc_cve_code, unique_desc_cve = pd.factorize(df['desc_cve'])
    unique_desc_cve = list(unique_desc_cve)

    msg_tokens = df['commit_mess']
    diff_tokens = df['diff_ori']

    msg_diff_tokens = msg_tokens + " " + diff_tokens
    msg_diff_tokens = list(msg_diff_tokens)

    labels = df['label']
    labels = list(labels)

    del df
    del msg_tokens
    del diff_tokens
    gc.collect()

    tokenizer = AutoTokenizer.from_pretrained("microsoft/codereviewer")

    preprocess_dir = Path(f'./preprocess_dataset/{name}')
    preprocess_dir.mkdir(parents=True, exist_ok=True)

    np.save(preprocess_dir / 'labels.npy', labels)

    cve_dir = preprocess_dir / 'cve'
    cve_dir.mkdir(parents=True, exist_ok=True)
    np.save(cve_dir / 'cve_code.npy', cve_code)
    np.save(cve_dir / 'cve.npy', unique_cve)

    desc_cve_dir = preprocess_dir / 'desc_cve'
    desc_cve_dir.mkdir(parents=True, exist_ok=True)
    np.save(preprocess_dir / 'desc_cve' / 'desc_cve_code.npy', desc_cve_code)
    batch_encode_texts(preprocess_dir / 'desc_cve', unique_desc_cve, tokenizer, batch_size=encode_batch_size)
    merge_pt(preprocess_dir / 'desc_cve' / f'encode_pt_{encode_batch_size}')

    batch_encode_texts(preprocess_dir / 'msg_diff_tokens', msg_diff_tokens, tokenizer, batch_size=encode_batch_size)
    merge_pt(preprocess_dir / 'msg_diff_tokens' / f'encode_pt_{encode_batch_size}')

    confirm_file = preprocess_dir / 'preprocess_confirm.tag'
    confirm_file.touch()


class NewCVEDataset(Dataset):
    def __init__(self, file_name, encode_batch_size=16):
        name = Path(file_name).stem
        preprocess_dir = Path(f'./preprocess_dataset/{name}')
        confirm_file = preprocess_dir / 'preprocess_confirm.tag'
        if not confirm_file.exists():
            preprocess(file_name, encode_batch_size)

        self.input_ids_desc = torch.load(preprocess_dir / 'desc_cve' / 'input_ids.pt')
        self.attention_mask_desc = torch.load(preprocess_dir / 'desc_cve' / 'attention_mask.pt')
        self.desc_tokens_codes = np.load(preprocess_dir / 'desc_cve' / 'desc_cve_code.npy')

        self.cve_codes = np.load(preprocess_dir / 'cve' / 'cve_code.npy')
        self.cve = np.load(preprocess_dir / 'cve' / 'cve.npy')

        self.labels = np.load(preprocess_dir / 'labels.npy')
        self.labels = self.labels.astype(np.float32)

        self.input_ids_msg_diff = torch.load(preprocess_dir / 'msg_diff_tokens' / 'input_ids.pt')
        self.attention_mask_msg_diff = torch.load(preprocess_dir / 'msg_diff_tokens' / 'attention_mask.pt')

    def __getitem__(self, index):
        desc_code = self.desc_tokens_codes[index]
        cve_code = self.cve_codes[index]
        return {
            'input_ids_desc': self.input_ids_desc[desc_code],
            'attention_mask_desc': self.attention_mask_desc[desc_code],
            'input_ids_msg_diff': self.input_ids_msg_diff[index],
            'attention_mask_msg_diff': self.attention_mask_msg_diff[index],
            'label': self.labels[index],
            'cve': self.cve[cve_code]
        }

    def __len__(self):
        return len(self.labels)
