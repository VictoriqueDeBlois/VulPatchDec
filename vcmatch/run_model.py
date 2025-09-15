from pathlib import Path

import numpy as np
import pandas as pd

from vc_code.model import logistic_regression, linear_regression, xgboost, lightgbm, cnn, get_rank

if __name__ == '__main__':
    feature_cols = ['bug_match', 'cve_match', 'web_match_nvd_links', 'issue_match_nvd_links', 'bug_match_nvd_links',
                    'func_same_cnt', 'func_same_ratio', 'func_unrelated_cnt', 'filepath_same_cnt',
                    'filepath_same_ratio', 'filepath_unrelated_cnt', 'file_same_cnt', 'file_same_ratio',
                    'file_unrelated_cnt', 'mess_shared_num', 'mess_shared_ratio', 'mess_max', 'mess_sum',
                    'mess_mean', 'mess_var', 'code_shared_num', 'code_shared_ratio', 'code_max', 'code_sum',
                    'code_mean', 'code_var']
    vuln_cols = ['vuln_emb' + str(i) for i in range(32)]
    cmt_cols = ['cmt_emb' + str(i) for i in range(32)]

    test_df = pd.read_feather('/home/xuhaoran/pycharm/Dual/data/final_data/new_test.feather')
    train_df = pd.read_json('/home/xuhaoran/pycharm/Dual/data/final_data/train.jsonl', lines=True)

    test_df = test_df.rename(columns={'commit_id': 'commit'})

    result = test_df[['cve', 'commit', 'label']]
    result.loc[:, 'prob_linear'] = 0
    result.loc[:, 'prob_logistic'] = 0
    result.loc[:, 'prob_xgb'] = 0
    result.loc[:, 'prob_lgb'] = 0
    result.loc[:, 'prob_cnn'] = 0

    train = train_df
    test = test_df

    train_dir = Path('train_encode')
    test_dir = Path('test_encode')

    train_desc_cve_code = np.load(train_dir / 'desc_cve_code.npy')
    train_desc_cve = np.load(train_dir / 'unique_desc_cve_emb.npy')
    train_commit_mess = np.load(train_dir / 'commit_mess_emb.npy')

    train_desc_cve_emb = train_desc_cve[train_desc_cve_code]
    train_df[[f'vuln_emb{i}' for i in range(32)]] = train_desc_cve_emb
    train_df[[f'cmt_emb{i}' for i in range(32)]] = train_commit_mess

    test_desc_cve_code = np.load(test_dir / 'desc_cve_code.npy')
    test_desc_cve = np.load(test_dir / 'unique_desc_cve_emb.npy')
    test_commit_mess = np.load(test_dir / 'commit_mess_emb.npy')

    test_desc_cve_emb = test_desc_cve[test_desc_cve_code]
    test_df[[f'vuln_emb{i}' for i in range(32)]] = test_desc_cve_emb
    test_df[[f'cmt_emb{i}' for i in range(32)]] = test_commit_mess

    X_train = train[feature_cols + vuln_cols + cmt_cols]
    y_train = train['label']
    X_test = test[feature_cols + vuln_cols + cmt_cols]
    y_test = test['label']

    # linear_regression
    linear_predict = linear_regression(X_train, y_train, X_test)
    result.loc[X_test.index, 'prob_linear'] = linear_predict
    # logistic_regression
    logistic_predict = logistic_regression(X_train, y_train, X_test)
    result.loc[X_test.index, 'prob_logistic'] = logistic_predict
    # xgboost
    xgb_predict = xgboost(X_train, y_train, X_test)
    result.loc[X_test.index, 'prob_xgb'] = xgb_predict
    # lightgbm
    lgb_predict = lightgbm(X_train, y_train, X_test)
    result.loc[X_test.index, 'prob_lgb'] = lgb_predict
    # cnn
    cnn_predict = cnn(X_train, y_train, X_test)
    result.loc[X_test.index, 'prob_cnn'] = cnn_predict[:, 1]

    # save rank result
    result['rank_linear'] = get_rank(result, ['prob_linear'])
    result['rank_logistic'] = get_rank(result, ['prob_logistic'])
    result['rank_xgb'] = get_rank(result, ['prob_xgb'])
    result['rank_lgb'] = get_rank(result, ['prob_lgb'])
    result['rank_cnn'] = get_rank(result, ['prob_cnn'])
    result.to_csv("./data/rank_result.csv", index=False)