from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import recall_score, precision_score, f1_score
from tqdm import tqdm


def padding(arrays, constant_values):
    max_length = max(len(arr) for arr in arrays)
    padded_arrays = []
    for arr in arrays:
        arr = np.array(arr, dtype=np.float64)
        padded = np.pad(arr, (0, max_length - len(arr)), mode='constant', constant_values=constant_values)
        padded_arrays.append(padded)
    return np.array(padded_arrays)

def evaluate(data: pd.DataFrame, k_values, item='cve', logit='logit', label='label', ascending=False):
    logits = []
    labels = []
    for index, group in data.groupby(item):
        logits.append(list(group[logit]))
        labels.append(list(group[label]))

    logits = padding(logits, constant_values=np.nan)
    labels = padding(labels, constant_values=0)
    if ascending:
        sort_indices = np.argsort(logits)
    else:
        sort_indices = np.argsort(-logits)

    results = []
    for k in k_values:
        top_indices = sort_indices[:, :k]

        y_pred = np.zeros_like(labels)

        row_indices = np.repeat(np.arange(top_indices.shape[0]), k)
        col_indices = top_indices.flatten()

        y_pred[row_indices, col_indices] = 1

        recall = recall_score(labels.T, y_pred.T, average='macro', zero_division=0)
        precision = precision_score(labels.T, y_pred.T, average='macro', zero_division=0)
        f1 = f1_score(labels.T, y_pred.T, average='macro', zero_division=0)
        results.append({
            'topk': k,
            'precision': precision,
            'recall': recall,
            'f1': f1,
        })
    return pd.DataFrame(results)

def find_threshold(data: pd.DataFrame, item='cve', logit='logit', label='label'):
    logits = []
    labels = []
    for index, group in data.groupby(item):
        logits.append(list(group[logit]))
        labels.append(list(group[label]))

    logits = padding(logits, constant_values=np.nan)
    labels = padding(labels, constant_values=0)

    results = []
    for i in tqdm(list(range(1, 1000))):
        threshold = i / 1000
        y_pred = logits > threshold
        f1 = f1_score(labels.T, y_pred.T, average='macro', zero_division=0)
        results.append((threshold, f1))

    best_threshold, best_f1 = max(results, key=lambda x: x[1])
    return best_threshold

def evaluate_threshold(data: pd.DataFrame, threshold, item='cve', logit='logit', label='label'):
    logits = []
    labels = []
    for index, group in data.groupby(item):
        logits.append(list(group[logit]))
        labels.append(list(group[label]))

    logits = padding(logits, constant_values=np.nan)
    labels = padding(labels, constant_values=0)

    y_pred = logits > threshold
    recall = recall_score(labels.T, y_pred.T, average='macro', zero_division=0)
    precision = precision_score(labels.T, y_pred.T, average='macro', zero_division=0)
    f1 = f1_score(labels.T, y_pred.T, average='macro', zero_division=0)
    return pd.DataFrame([{
        'threshold': threshold,
        'precision': precision,
        'recall': recall,
        'f1': f1,
    }])

def eval_data(output_csv):
    output_csv = Path(output_csv)
    name = output_csv.stem
    name = name[:-len('_output')]

    k_values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 30, 50, 100]
    df = pd.read_csv(output_csv)
    result = evaluate(df, k_values)
    result.to_csv(f'{name}_topk_result.csv', index=False)
    best = find_threshold(df)
    result = evaluate_threshold(df, best)
    result.to_csv(f'{name}_threshold_result.csv', index=False)

if __name__ == '__main__':
    current_dir = Path('.')
    output_files = list(current_dir.glob('*_output.csv'))
    done = 0
    for output_csv in output_files:
        print(f'output: {done} / {len(output_files)}')
        eval_data(output_csv)
        done += 1

    df = pd.read_csv('./vcmatch_rank.csv')
    k_values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 30, 50, 100]
    result = evaluate(df, k_values, logit='rank_fusion_voting', ascending=True)
    result.to_csv(f'vcmatch_topk_result.csv', index=False)

