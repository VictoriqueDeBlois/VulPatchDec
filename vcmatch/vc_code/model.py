import logging
import math
import os
import warnings

import lightgbm as lgb
import xgboost as xgb
from sklearn.linear_model import LinearRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import mean_squared_log_error
from sklearn.model_selection import KFold

import torch
import torch.nn.functional as F
import torch.optim as optim
import torch.nn as nn
import numpy as np
import pandas as pd
from torch.utils.data import Dataset, DataLoader
from tqdm import tqdm

from .encoding_module import *

warnings.filterwarnings('ignore')

def setup_logging(log_file_name):
    logger = logging.getLogger(f'worker_{os.getpid()}')
    logger.setLevel(logging.INFO)

    # 为每个进程创建单独的文件处理器
    if not logger.handlers:
        handler = logging.FileHandler(f'./{log_file_name}_{os.getpid()}.log', encoding='utf-8')
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

logger = setup_logging('vcmatch')


# ============ Linear Regression ============
def linear_regression(X_train, y_train, X_test):
    model = LinearRegression()
    model.fit(X_train, y_train)
    predict = model.predict(X_test)
    return predict


# ============ Logistic Regression ============
def logistic_regression(X_train, y_train, X_test):
    model = LogisticRegression(
        class_weight='balanced', solver='saga', multi_class='ovr', n_jobs=5, max_iter=200)
    model.fit(X_train, y_train)
    predict = model.predict(X_test)
    return predict


# ============ XGBoost ============
def xgboost(X_train, y_train, X_test):
    # prefix = "xgb_"
    param = {
        'max_depth': 5,
        'eta': 0.05,
        'verbosity': 1,
        'random_state': 2021,
        'objective': 'binary:logistic',
        'tree_method': 'gpu_hist'
    }

    def myFeval(preds, dtrain):
        labels = dtrain.get_label()
        return 'error', math.sqrt(mean_squared_log_error(preds, labels))
    print("XGBoost 训练 & 预测")
    xgb_train = xgb.DMatrix(X_train, y_train)
    model = xgb.train(param, xgb_train, num_boost_round=500, feval=myFeval)
    predict = model.predict(xgb.DMatrix(X_test))
    return predict


# ============ LightGBM ============
def lightgbm(X_train, y_train, X_test):
    # prefix = "lgb_"
    param = {'device': 'gpu',
             'learning_rate': 0.04,
             'max_depth': 5,
             'verbose': -1
             }
    print("LGBM 训练 & 预测")
    model = lgb.train(param, lgb.Dataset(
        data=X_train, label=y_train), num_boost_round=500)
    predict = model.predict(X_test)
    return predict


# ============ CNN ============
class CNNDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(X.to_numpy(dtype=np.float32), dtype=torch.float)
        self.y = torch.tensor(y.to_numpy(dtype=np.int64), dtype=torch.long)
        self.len = self.X.shape[0]

    def __len__(self):
        return self.len

    def __getitem__(self, idx):
        data = self.X[idx]
        label = self.y[idx]
        return data, label


class FocalLoss(nn.Module):
    def __init__(self, class_num, alpha=None, gamma=2, size_average=True):
        super(FocalLoss, self).__init__()
        if alpha is None:
            self.alpha = torch.tensor(torch.ones(class_num, 1), requires_grad=True)
        else:
            self.alpha = alpha
        self.gamma = gamma
        self.class_num = class_num
        self.size_average = size_average

    def forward(self, inputs, targets):
        N = inputs.size(0)
        C = inputs.size(1)
        P = F.softmax(inputs, dim=1)
        class_mask = inputs.data.new(N, C).fill_(0)
        class_mask = torch.tensor(class_mask)
        ids = targets.view(-1, 1)
        class_mask.scatter_(1, ids.data, 1.)
        if inputs.is_cuda and not self.alpha.is_cuda:
            self.alpha = self.alpha.cuda()
        alpha = self.alpha[ids.data.view(-1)]
        probs = (P*class_mask).sum(1).view(-1, 1)
        log_p = probs.log()
        batch_loss = -alpha*(torch.pow((1-probs), self.gamma))*log_p
        if self.size_average:
            loss = batch_loss.mean()
        else:
            loss = batch_loss.sum()
        return loss


class Net(nn.Module):
    def __init__(self, num_feature):
        super(Net, self).__init__()
        self.model = nn.Sequential(
            nn.Linear(num_feature, 32),
            nn.Linear(32, 8),
            nn.Linear(8, 2)
        )
        self.soft = nn.Softmax()

    def forward(self, input_):
        s1 = self.model(input_)
        out = self.soft(s1)
        return out


def cnn(X_train, y_train, X_test):
    lr = 0.001
    num_workers = 10
    alpha = 10
    batch_size = 10000
    num_epoches = 20
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    criterion = FocalLoss(class_num=2, alpha=torch.tensor([1, 100]))

    train_dataset = CNNDataset(X_train, y_train)
    test_dataset = CNNDataset(X_test, pd.Series([1]*X_test.shape[0]))
    num_feature = X_train.shape[1]
    model = Net(num_feature).to(device)
    optimizer = optim.Adam(model.parameters(), lr=lr)
    train_dataloader = DataLoader(dataset=train_dataset,
                                  batch_size=batch_size,
                                  shuffle=False,
                                  num_workers=num_workers,
                                  pin_memory=False)
    test_dataloader = DataLoader(dataset=test_dataset,
                                 batch_size=batch_size,
                                 shuffle=False,
                                 num_workers=num_workers,
                                 pin_memory=False)

    print("CNN 训练 & 预测")
    for epoch in tqdm(range(num_epoches), total=num_epoches):
        model.train()
        predict = []
        t1 = time.time()
        for i, (data, label) in enumerate(train_dataloader):
            data = data.to(device)
            label = label.to(device)
            label_size = data.size()[0]
            pred = model(data)
            loss = criterion(pred, label)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
        t2 = time.time()
        logger.info('Epoch [{}/{}], Time {}s, Loss: {:.4f}, Lr:{:.4f}'.format(
            epoch + 1, num_epoches, int(t2 - t1), loss.item(), lr))
        torch.save(model.state_dict(),
                   './data/cnn_20_{:02}.ckpt'.format(epoch))

    model.eval()
    with torch.no_grad():
        predict = []
        for i, (data, label) in enumerate(test_dataloader):
            data = data.to(device)
            pred = model(data)
            pred = pred.cpu().detach().numpy()
            predict.extend(pred)
        predict = np.array(predict)
        return predict


# ============ PatchScout ============
class RankNet(nn.Module):
    def __init__(self, num_feature):
        super(RankNet, self).__init__()
        self.model = nn.Sequential(
            nn.Linear(num_feature, 32),
            # nn.Dropout(0.1),
            # nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(32, 16),
            #  nn.Dropout(0.1),
            #  nn.LeakyReLU(0.2, inplace=True),
            nn.Linear(16, 1))
        self.output_sig = nn.Sigmoid()

    def forward(self, input_1, input_2):
        s1 = self.model(input_1)
        s2 = self.model(input_2)
        out = self.output_sig(s1 - s2)
        return out

    def predict(self, input_):
        s = self.model(input_)
        return s


def create_pair_data(df):
    label = []
    array_0, array_1 = [], []
    idx = 0
    for cve, tmp_df in df.groupby(['cve']):
        true = tmp_df[tmp_df['label'] == 1]
        false = tmp_df[tmp_df['label'] == 0]
        for true_item in true.iterrows():
            idx += 1
            if idx % 2 == 0:
                array_1.extend(
                    [np.array(true_item[1].drop(['label'], axis=1))] * 5000)
                array_0.extend(np.array(false.drop(['label'], axis=1)))
                label.extend([1]*5000)
            else:
                array_0.extend(
                    [np.array(true_item[1].drop(['label'], axis=1))] * 5000)
                array_1.extend(np.array(false.drop(['label'], axis=1)))
                label.extend([0]*5000)
    return len(array_0), array_0, array_1, label


class PairDataset(Dataset):
    def __init__(self, df):
        self.datanum, self.array_0, self.array_1, self.label = create_pair_data(
            df)

    def __len__(self):
        return self.datanum

    def __getitem__(self, idx):
        data1 = torch.from_numpy(self.array_0[idx]).float()
        data2 = torch.from_numpy(self.array_1[idx]).float()
        label = torch.tensor(self.label[idx])
        return data1, data2, label


def patchScout(X_train, y_train, X_test, y_test):
    lr = 0.001
    num_workers = 10
    alpha = 10
    batch_size = 10000
    num_epoches = 20
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    criterion = nn.BCELoss()

    train_copy = X_train.copy()
    train_copy['label'] = y_train
    train_dataset = PairDataset(train_copy)
    test_copy = X_test.copy()
    test_copy['label'] = y_test
    test_dataset = PairDataset(test_copy)

    num_feature = X_train.shape[1]
    model = RankNet(num_feature).to(device)
    optimizer = optim.Adam(model.parameters(), lr=lr)
    train_dataloader = DataLoader(dataset=train_dataset,
                                  batch_size=batch_size,
                                  shuffle=False,
                                  num_workers=num_workers,
                                  pin_memory=False)
    test_dataloader = DataLoader(dataset=test_dataset,
                                 batch_size=batch_size,
                                 shuffle=False,
                                 num_workers=num_workers,
                                 pin_memory=False)

    print("ps 训练 & 预测")
    for epoch in range(num_epoches):
        model.train()
        t1 = time.time()

        for i, (data1, data2, label) in enumerate(train_dataloader):
            data1 = data1.to(device)
            data2 = data2.to(device)
            label = label.to(device)
            pred = model(data1, data2)
            label_size = data1.size()[0]
            loss = criterion(pred, label.unsqueeze(1).float())
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            pred = pred.cpu().detach().numpy()
            pred = [0 if item[0] <= 0.5 else 1 for item in pred]
            label = label.cpu().detach().numpy()
            x = np.bitwise_xor(pred, label)
            res.extend(x)
        res = np.numpy(res)
        t2 = time.time()
        logger.info('Epoch [{}/{}], Time {}s, Loss: {:.4f}, Lr:{:.4f}'.format(
            epoch + 1, num_epoches, int(t2 - t1), loss.item(), lr))
        torch.save(model.state_dict(),
                   '../data/ps_20_{:02}.ckpt'.format(epoch))

    model.eval()
    predict = []
    with torch.no_grad():
        for i, (data1, data2, label) in enumerate(test_dataloader):
            data1 = data1.to(device)
            data2 = data2.to(device)
            pred = model(data1, data2)
            pred = pred.cpu().detach().numpy()
            pred = [0 if item[0] <= 0.5 else 1 for item in pred]
            label = label.cpu().detach().numpy()
            x = np.bitwise_xor(pred, label)
            predict.extend(x)
    return predict


# ======================== metric ========================

# sort data based on 'sortby' list, and then get the rank of each data
def get_rank(df, sortby, ascending=False):
    gb = df.groupby('cve')
    l = []
    for item1, item2 in gb:
        item2 = item2.reset_index()
        item2 = item2.sort_values(sortby + ['commit'], ascending=ascending)
        item2 = item2.reset_index(drop=True).reset_index()
        l.append(item2[['index', 'level_0']])

    df = pd.concat(l)
    df['rank'] = df['level_0']+1
    df = df.sort_values(['index'], ascending=True).reset_index(drop=True)
    return df['rank']


# get metric
def get_score(test, rankname='rank', N=10):
    cve_list = []
    cnt = 0
    total = []
    gb = test.groupby('cve')
    for item1, item2 in gb:
        item2 = item2.sort_values(
            [rankname], ascending=True).reset_index(drop=True)
        idx = item2[item2.label == 1].index[0]+1
        if idx <= N:
            total.append(idx)
            cnt += 1
        else:
            total.append(N)
            cve_list.append(item1)
    return np.mean(total), cnt / len(total)


def get_score2(predict, N=10):
    length = len(predict)
    cnt = length//5000
    sum_arr = []
    for i in range(cnt):
        arr = predict[i*5000: (i+1)*5000]
        sum_arr.append(sum(arr)+1)
    arr1 = [item if item <= N else N for item in sum_arr]
    arr2 = [1 if item <= N else 0 for item in sum_arr]
    return np.mean(arr1), sum(arr2) / cnt

# get metrix on top 1-10


def get_full_score(df, suffix, result, start=1, end=10):
    metric1_list = []
    metric2_list = []
    for i in range(start, end+1):
        metric1, metric2 = get_score(df, 'rank_'+suffix, i)
        metric1_list.append(metric1)
        metric2_list.append(metric2)
    result['metric1_'+suffix] = metric1_list
    result['metric2_'+suffix] = metric2_list
    return result


def get_full_score2(predict, suffix, result, start=1, end=10):
    metric1_list = []
    metric2_list = []
    for i in range(start, end+1):
        metric1, metric2 = get_score2(predict)
        metric1_list.append(metric1)
        metric2_list.append(metric2)
    result['metric1_'+suffix] = metric1_list
    result['metric2_'+suffix] = metric2_list
    return result

if __name__ == '__main__':

    # ======================== 5-fold cross-validation ========================
    df = pd.read_csv("../dataset/Dataset_5000.csv")
    cvelist = df.cve.unique()
    kf = KFold(n_splits=5, shuffle=True)


    feature_cols = ['addcnt', 'delcnt', 'totalcnt', 'issue_cnt', 'web_cnt', 'bug_cnt', 'cve_cnt',
                    'time_dis', 'inter_token_cwe_cnt', 'inter_token_cwe_ratio', 'vuln_commit_tfidf',
                    'cve_match', 'bug_match', 'func_same_cnt', 'func_same_ratio', 'func_unrelated_cnt',
                    'filepath_same_cnt', 'filepath_same_ratio', 'filepath_unrelated_cnt',
                    'file_same_cnt', 'file_same_ratio', 'file_unrelated_cnt', 'patchlike', 'vuln_type_1',
                    'vuln_type2', 'vuln_type3', 'mess_shared_num', 'mess_shared_ratio',
                    'mess_max', 'mess_sum', 'mess_mean', 'mess_var', 'code_shared_num',
                    'code_shared_ratio', 'code_max', 'code_sum', 'code_mean', 'code_var']
    vuln_cols = ['vuln_emb' + str(i) for i in range(32)]
    cmt_cols = ['cmt_emb' + str(i) for i in range(32)]
    ps_cols = ['cve_match', 'bug_match', 'func_same_cnt', 'func_same_ratio', 'func_unrelated_cnt',
               'filepath_same_cnt', 'filepath_same_ratio', 'filepath_unrelated_cnt',
               'file_same_cnt', 'file_same_ratio', 'file_unrelated_cnt', 'patchlike', 'vuln_type_1',
               'vuln_type2', 'vuln_type3', 'mess_shared_num', 'mess_shared_ratio',
               'mess_max', 'mess_sum', 'mess_mean', 'mess_var', 'code_shared_num',
               'code_shared_ratio', 'code_max', 'code_sum', 'code_mean', 'code_var']

    result = df[['cve', 'commit', 'label']]
    result.loc[:, 'prob_linear'] = 0
    result.loc[:, 'prob_logistic'] = 0
    result.loc[:, 'prob_xgb'] = 0
    result.loc[:, 'prob_lgb'] = 0
    result.loc[:, 'prob_cnn'] = 0

    for idx, (train_index, test_index) in enumerate(kf.split(cvelist)):
        cve_train = cvelist[train_index]
        isTrain = df.cve.apply(lambda item: item in cve_train)
        train = df[isTrain]
        test = df[isTrain == False]
        tmp_train = train[['cve', 'repo', 'commit']].copy()
        tmp_test = test[['cve', 'repo', 'commit']].copy()
        note = 'idx_'+idx
        encoding(tmp_train, tmp_test, note)
        outpath = '../data/encode/'
        train[vuln_cols] = readfile(outpath + 'vuln_embedding_train')
        train[cmt_cols] = readfile(outpath + 'commit_embedding_train')
        test[vuln_cols] = readfile(outpath + 'vuln_embedding_test')
        test[cmt_cols] = readfile(outpath + 'commit_embedding_test')

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
        result.loc[X_test.index, 'prob_cnn'] = cnn_predict
        # patchscout
        patchScout_predict = patchScout(X_train[ps_cols], y_train, X_test[ps_cols], y_test)


    # save rank result
    result['rank_linear'] = get_rank(result, ['prob_linear'])
    result['rank_logistic'] = get_rank(result, ['prob_logistic'])
    result['rank_xgb'] = get_rank(result, ['prob_xgb'])
    result['rank_lgb'] = get_rank(result, ['prob_lgb'])
    result['rank_cnn'] = get_rank(result, ['prob_cnn'])
    result.to_csv("../data/rank_result.csv", index=False)


    # save metric result
    result2 = pd.DataFrame()
    result2 = get_full_score(result, 'linear', result2)
    result2 = get_full_score(result, 'logistic', result2)
    result2 = get_full_score(result, 'xgb', result2)
    result2 = get_full_score(result, 'lgb', result2)
    result2 = get_full_score(result, 'cnn', result2)
    result2 = get_full_score2(patchScout_predict, 'ps', result2)
    result2.to_csv("../data/metric_result.csv", index=False)


    # =============== model fusion ===============

    def fusion_max(result, cols):
        def get_max(row, columns):
            return max([row[column] for column in columns])

        result['fusion_max'] = result.apply(lambda row: get_max(row, cols), axis=1)
        result['rank_fusion_max'] = get_rank(result, ['fusion_max'], False)
        result.drop(['fusion_max'], axis=1)
        return result


    def fusion_min(result, cols):
        def get_min(row, columns):
            return min([row[column] for column in columns])

        result['fusion_min'] = result.apply(lambda row: get_min(row, cols), axis=1)
        result['rank_fusion_min'] = get_rank(result, ['fusion_min'], False)
        result.drop(['fusion_min'], axis=1)
        return result


    def fusion_sum(result, cols):
        def get_sum(row, columns):
            return sum([row[column] for column in columns])

        result['fusion_sum'] = result.apply(lambda row: get_sum(row, cols), axis=1)
        result['rank_fusion_sum'] = get_rank(result, ['fusion_sum'], False)
        result.drop(['fusion_sum'], axis=1)
        return result


    def fusion_borda(row, cols):
        def get_sum(row, columns):
            return sum([row[column] for column in columns])

        result['fusion_borda'] = result.apply(
            lambda row: get_sum(row, cols), axis=1)
        result['rank_fusion_borda'] = get_rank(result, ['fusion_borda'], True)
        result.drop(['fusion_borda'], axis=1)
        return result


    def fusion_voting(result, cols, suffix=''):
        def get_closest(row, columns):
            l = [row[column] for column in columns]
            l.sort()
            if l[1] - l[0] >= l[2] - l[1]:
                return l[1]+l[2]
            else:
                return l[1]+l[0]

        result['closest'] = result.apply(
            lambda row: get_closest(row, cols), axis=1)
        result['sum'] = 0
        for column in columns:
            result['sum'] = result['sum'] + result[column]
        result['last'] = result['sum'] - result['closest']
        result['rank_fusion_voting' +
               suffix] = get_rank(result, ['closest', 'last'], True)
        result.drop(['sum', 'closest', 'last'], axis=1)
        return result


    # save rank result
    result = pd.read_csv('../data/rank_result.csv')
    tmp_col1 = ['prob_xgb', 'prob_lgb', 'prob_cnn']
    tmp_col2 = ['rank_xgb', 'rank_lgb', 'rank_cnn']
    result = fusion_max(result, tmp_col1)
    result = fusion_min(result, tmp_col1)
    result = fusion_sum(result, tmp_col1)
    result = fusion_borda(result, tmp_col2)
    result = fusion_voting(result, tmp_col2)
    result.to_csv("../data/rank_fusion_result.csv", index=False)


    # save metric result
    result2 = pd.DataFrame()
    result2 = get_full_score(result, 'fusion_max', result2)
    result2 = get_full_score(result, 'fusion_min', result2)
    result2 = get_full_score(result, 'fusion_sum', result2)
    result2 = get_full_score(result, 'fusion_borda', result2)
    result2 = get_full_score(result, 'fusion_voting', result2)
    result2.to_csv("../data/metric_fusion_result.csv", index=False)


    # ======== each feature dimension ========


    result = df[['cve', 'commit', 'label']]
    result.loc[:, 'prob_xgb'] = 0
    result.loc[:, 'prob_lgb'] = 0
    result.loc[:, 'prob_cnn'] = 0
    features = [['addcnt', 'delcnt', 'totalcnt'],
                ['issue_cnt', 'web_cnt', 'bug_cnt','cve_cnt', 'cve_match', 'bug_match', 'patchlike', 'vuln_type_1', 'vuln_type2', 'vuln_type3'],
                ['time_dis', 'func_same_cnt', 'func_same_ratio', 'func_unrelated_cnt', 'filepath_same_cnt', 'filepath_same_ratio',
                'filepath_unrelated_cnt', 'file_same_cnt', 'file_same_ratio', 'file_unrelated_cnt'],
                ['inter_token_cwe_cnt', 'inter_token_cwe_ratio','vuln_commit_tfidf', 'mess_shared_num', 'mess_shared_ratio',  'mess_max',
                'mess_sum', 'mess_mean', 'mess_var', 'code_shared_num',  'code_shared_ratio', 'code_max', 'code_sum','code_mean', 'code_var'],
                ['vuln_emb' + str(i) for i in range(32)],
                ['cmt_emb' + str(i) for i in range(32)]]

    total_features = []
    for i in range(6):
        total_features.extend(features[i])


    for idx, (train_index, test_index) in enumerate(kf.split(cvelist)):
        cve_train = cvelist[train_index]
        isTrain = df.cve.apply(lambda item: item in cve_train)
        train = df[isTrain]
        test = df[isTrain == False]
        tmp_train = train[['cve', 'repo', 'commit']].copy()
        tmp_test = test[['cve', 'repo', 'commit']].copy()
        note = 'idx_'+idx
        encoding(tmp_train, tmp_test, note)
        outpath = '../data/encode/'
        train[vuln_cols] = readfile(outpath + 'vuln_embedding_train')
        train[cmt_cols] = readfile(outpath + 'commit_embedding_train')
        test[vuln_cols] = readfile(outpath + 'vuln_embedding_test')
        test[cmt_cols] = readfile(outpath + 'commit_embedding_test')

        for i in range(6):
            suffix = "_"+str(i)
            X_train = train[total_features - features[i]]
            y_train = train['label']
            X_test = test[total_features - features[i]]

            xgb_predict = xgboost(X_train, y_train, X_test)
            result.loc[X_test.index, 'prob_xgb'+suffix] = xgb_predict
            lgb_predict = lightgbm(X_train, y_train, X_test)
            result.loc[X_test.index, 'prob_lgb'+suffix] = lgb_predict
            cnn_predict = cnn(X_train, y_train, X_test)
            result.loc[X_test.index, 'prob_cnn'+suffix] = cnn_predict


    result2 = pd.Dataframe()
    # save rank result
    for i in range(6):
        suffix = "_"+str(i)
        result['rank_xgb'+suffix] = get_rank(result, ['prob_xgb'+suffix])
        result['rank_lgb'+suffix] = get_rank(result, ['prob_lgb'+suffix])
        result['rank_cnn'+suffix] = get_rank(result, ['prob_cnn'+suffix])
        tmp_col2 = ['rank_xgb'+suffix, 'rank_lgb'+suffix, 'rank_cnn'+suffix]
        result = fusion_voting(result, tmp_col2)
        result2 = get_full_score(result, 'fusion_voting'+suffix, result2)
    result.to_csv("../data/rank_result_feature.csv", index=False)
    result2.to_csv("../data/metric_result_feature.csv", index=False)


    # ============== each repo ==============
    df = pd.read_csv("../dataset/Dataset_5000.csv")
    cvelist = df.cve.unique()
    repos = df.repo.unique()

    feature_cols = ['addcnt', 'delcnt', 'totalcnt', 'issue_cnt', 'web_cnt', 'bug_cnt', 'cve_cnt',
                    'time_dis', 'inter_token_cwe_cnt', 'inter_token_cwe_ratio', 'vuln_commit_tfidf',
                    'cve_match', 'bug_match', 'func_same_cnt', 'func_same_ratio', 'func_unrelated_cnt',
                    'filepath_same_cnt', 'filepath_same_ratio', 'filepath_unrelated_cnt',
                    'file_same_cnt', 'file_same_ratio', 'file_unrelated_cnt', 'patchlike', 'vuln_type_1',
                    'vuln_type2', 'vuln_type3', 'mess_shared_num', 'mess_shared_ratio',
                    'mess_max', 'mess_sum', 'mess_mean', 'mess_var', 'code_shared_num',
                    'code_shared_ratio', 'code_max', 'code_sum', 'code_mean', 'code_var']
    vuln_cols = ['vuln_emb' + str(i) for i in range(32)]
    cmt_cols = ['cmt_emb' + str(i) for i in range(32)]

    result = df[['cve', 'repo', 'commit', 'label']]
    result.loc[:, 'prob_xgb'] = 0
    result.loc[:, 'prob_lgb'] = 0
    result.loc[:, 'prob_cnn'] = 0


    for repo in repos:
        train = df[df.repo == repo]
        test = df[df.repo != repo]
        tmp_train = train[['cve', 'repo', 'commit']].copy()
        tmp_test = test[['cve', 'repo', 'commit']].copy()
        note = repo
        encoding(tmp_train, tmp_test, note)
        outpath = '../data/encode/'
        train[vuln_cols] = readfile(outpath + 'vuln_embedding_train')
        train[cmt_cols] = readfile(outpath + 'commit_embedding_train')
        test[vuln_cols] = readfile(outpath + 'vuln_embedding_test')
        test[cmt_cols] = readfile(outpath + 'commit_embedding_test')

        X_train = train[feature_cols + vuln_cols + cmt_cols]
        y_train = train['label']
        X_test = test[feature_cols + vuln_cols + cmt_cols]
        y_test = test['label']

        xgb_predict = xgboost(X_train, y_train, X_test)
        result.loc[X_test.index, 'prob_xgb'+note] = predict
        lgb_predict = lightgbm(X_train, y_train, X_test)
        result.loc[X_test.index, 'prob_lgb'+note] = predict
        cnn_predict = cnn(X_train, y_train, X_test)
        result.loc[X_test.index, 'prob_cnn'+note] = predict
        result.loc[:, 'rank_xgb'+note] = 0
        result.loc[:, 'rank_lgb'+note] = 0
        result.loc[:, 'rank_cnn'+note] = 0
        result.loc[X_test.index, 'rank_xgb' +
                   note] = get_rank(result.loc[X_test.index], ['prob_xgb'+note])
        result.loc[X_test.index, 'rank_lgb' +
                   note] = get_rank(result.loc[X_test.index], ['prob_lgb'+note])
        result.loc[X_test.index, 'rank_cnn' +
                   note] = get_rank(result.loc[X_test.index], ['prob_cnn'+note])


    result2 = pd.Dataframe()
    # save rank result
    for repo in repos:
        suffix = repo
        tmp_result = result[result.repo == repo]
        tmp_result['rank_xgb'+suffix] = get_rank(tmp_result, ['prob_xgb'+suffix])
        tmp_result['rank_lgb'+suffix] = get_rank(tmp_result, ['prob_lgb'+suffix])
        tmp_result['rank_cnn'+suffix] = get_rank(tmp_result, ['prob_cnn'+suffix])
        tmp_col2 = ['rank_xgb'+suffix, 'rank_lgb'+suffix, 'rank_cnn'+suffix]
        tmp_result = fusion_voting(tmp_result, tmp_col2)
        result2 = get_full_score(tmp_result, 'fusion_voting'+suffix, result2)
    result.to_csv("../data/rank_result_repo.csv", index=False)
    result2.to_csv("../data/metric_result_repo.csv", index=False)
