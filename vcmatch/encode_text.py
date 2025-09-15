import os
from pathlib import Path

import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from transformers import BertTokenizer, BertModel
from sklearn.model_selection import train_test_split
import numpy as np
from tqdm import tqdm

class TextPairDataset(Dataset):
    """文本对数据集类"""
    def __init__(self, text1_list, text2_list, labels, tokenizer, max_length=128):
        self.text1_list = text1_list
        self.text2_list = text2_list
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.text1_list)

    def __getitem__(self, idx):
        text1 = str(self.text1_list[idx])
        text2 = str(self.text2_list[idx])
        label = self.labels[idx]

        # 对两段文本分别进行tokenize
        encoding1 = self.tokenizer(
            text1,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )

        encoding2 = self.tokenizer(
            text2,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )

        return {
            'text1_input_ids': encoding1['input_ids'].flatten(),
            'text1_attention_mask': encoding1['attention_mask'].flatten(),
            'text2_input_ids': encoding2['input_ids'].flatten(),
            'text2_attention_mask': encoding2['attention_mask'].flatten(),
            'label': torch.tensor(label, dtype=torch.long)
        }

class BertTextEncoder(nn.Module):
    """BERT文本编码器模型"""
    def __init__(self, bert_model_name='bert-base-uncased', dropout_rate=0.3):
        super(BertTextEncoder, self).__init__()

        # 加载BERT模型
        self.bert = BertModel.from_pretrained(bert_model_name)

        # 文本编码器：768 -> 256 -> 32
        self.text_encoder = nn.Sequential(
            nn.Linear(768, 256),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(256, 32),
            nn.ReLU()
        )

        # 二分类器：64 (32+32) -> 1
        self.classifier = nn.Sequential(
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            nn.Linear(32, 2)
        )

        # 初始化权重
        self._init_weights()

    def _init_weights(self):
        """初始化线性层权重"""
        for module in [self.text_encoder, self.classifier]:
            for layer in module:
                if isinstance(layer, nn.Linear):
                    nn.init.xavier_uniform_(layer.weight)
                    nn.init.zeros_(layer.bias)

    def encode_text(self, input_ids, attention_mask):
        """编码单个文本，返回32维embedding"""
        with torch.no_grad():
            bert_output = self.bert(input_ids=input_ids, attention_mask=attention_mask)
            pooled_output = bert_output.pooler_output  # [batch_size, 768]
            text_embedding = self.text_encoder(pooled_output)  # [batch_size, 32]
        return text_embedding

    def forward(self, text1_input_ids, text1_attention_mask, text2_input_ids, text2_attention_mask):
        # 获取两个文本的BERT表示
        bert_output1 = self.bert(input_ids=text1_input_ids, attention_mask=text1_attention_mask)
        bert_output2 = self.bert(input_ids=text2_input_ids, attention_mask=text2_attention_mask)

        # 获取pooled output (CLS token representation)
        pooled_output1 = bert_output1.pooler_output  # [batch_size, 768]
        pooled_output2 = bert_output2.pooler_output  # [batch_size, 768]

        # 通过文本编码器得到32维embedding
        text1_embedding = self.text_encoder(pooled_output1)  # [batch_size, 32]
        text2_embedding = self.text_encoder(pooled_output2)  # [batch_size, 32]

        # 连接两个embedding
        combined_embedding = torch.cat([text1_embedding, text2_embedding], dim=1)  # [batch_size, 64]

        # 通过分类器进行二分类
        logits = self.classifier(combined_embedding)  # [batch_size, 2]

        return logits, text1_embedding, text2_embedding

def train_model(model, train_loader, val_loader, num_epochs=5, learning_rate=2e-5):
    """训练模型"""
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model.to(device)

    optimizer = optim.AdamW(model.parameters(), lr=learning_rate)
    criterion = nn.CrossEntropyLoss()

    # 学习率调度器
    scheduler = optim.lr_scheduler.StepLR(optimizer, step_size=2, gamma=0.8)

    train_losses = []
    val_losses = []
    val_accuracies = []

    for epoch in range(num_epochs):
        # 训练阶段
        model.train()
        total_train_loss = 0
        train_progress = tqdm(train_loader, desc=f'Epoch {epoch+1}/{num_epochs} - Training')

        for batch in train_progress:
            optimizer.zero_grad()

            # 将数据移到设备
            text1_input_ids = batch['text1_input_ids'].to(device)
            text1_attention_mask = batch['text1_attention_mask'].to(device)
            text2_input_ids = batch['text2_input_ids'].to(device)
            text2_attention_mask = batch['text2_attention_mask'].to(device)
            labels = batch['label'].to(device)

            # 前向传播
            logits, _, _ = model(text1_input_ids, text1_attention_mask,
                                 text2_input_ids, text2_attention_mask)

            loss = criterion(logits, labels)

            # 反向传播
            loss.backward()
            optimizer.step()

            total_train_loss += loss.item()
            train_progress.set_postfix({'loss': loss.item()})

        avg_train_loss = total_train_loss / len(train_loader)
        train_losses.append(avg_train_loss)

        # 验证阶段
        model.eval()
        total_val_loss = 0
        correct_predictions = 0
        total_predictions = 0

        with torch.no_grad():
            for batch in tqdm(val_loader, desc='Validation'):
                text1_input_ids = batch['text1_input_ids'].to(device)
                text1_attention_mask = batch['text1_attention_mask'].to(device)
                text2_input_ids = batch['text2_input_ids'].to(device)
                text2_attention_mask = batch['text2_attention_mask'].to(device)
                labels = batch['label'].to(device)

                logits, _, _ = model(text1_input_ids, text1_attention_mask,
                                     text2_input_ids, text2_attention_mask)

                loss = criterion(logits, labels)
                total_val_loss += loss.item()

                # 计算准确率
                _, predicted = torch.max(logits.data, 1)
                total_predictions += labels.size(0)
                correct_predictions += (predicted == labels).sum().item()

        avg_val_loss = total_val_loss / len(val_loader)
        val_accuracy = correct_predictions / total_predictions

        val_losses.append(avg_val_loss)
        val_accuracies.append(val_accuracy)

        # 更新学习率
        scheduler.step()

        print(f'Epoch {epoch+1}/{num_epochs}:')
        print(f'  Train Loss: {avg_train_loss:.4f}')
        print(f'  Val Loss: {avg_val_loss:.4f}')
        print(f'  Val Accuracy: {val_accuracy:.4f}')
        print('-' * 50)

    return train_losses, val_losses, val_accuracies

def create_sample_data(num_samples=1000):
    """创建示例数据"""
    np.random.seed(42)

    # 示例文本数据
    texts1 = [
                 "This is a positive sentiment text",
                 "I love this product very much",
                 "The weather is terrible today",
                 "Amazing experience with great service"
             ] * (num_samples // 4)

    texts2 = [
                 "This text also shows positive sentiment",
                 "Great quality and fast delivery",
                 "Bad weather makes me sad",
                 "Excellent customer support team"
             ] * (num_samples // 4)

    # 生成标签 (0: 不相似, 1: 相似)
    labels = [1, 1, 0, 1] * (num_samples // 4)

    return texts1[:num_samples], texts2[:num_samples], labels[:num_samples]

def main():
    """主函数"""
    # 设置随机种子
    torch.manual_seed(42)
    np.random.seed(42)

    train_df = pd.read_json('/home/xuhaoran/pycharm/Dual/data/final_data/train.jsonl', lines=True)
    val_df = pd.read_json('/home/xuhaoran/pycharm/Dual/data/final_data/val.jsonl', lines=True)

    train_texts1 = train_df['desc_cve']
    train_texts2 = train_df['commit_mess']
    train_labels = train_df['label']

    val_texts1 = val_df['desc_cve']
    val_texts2 = val_df['commit_mess']
    val_labels = val_df['label']

    # 初始化tokenizer
    print("加载BERT tokenizer...")
    tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')

    # 创建数据集
    train_dataset = TextPairDataset(train_texts1, train_texts2, train_labels, tokenizer)
    val_dataset = TextPairDataset(val_texts1, val_texts2, val_labels, tokenizer)

    # 创建数据加载器
    train_loader = DataLoader(train_dataset, batch_size=16, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=16, shuffle=False)

    # 初始化模型
    print("初始化BERT模型...")
    model = BertTextEncoder()

    # 训练模型
    print("开始训练...")
    train_losses, val_losses, val_accuracies = train_model(
        model, train_loader, val_loader, num_epochs=1, learning_rate=2e-5
    )

    print(train_losses, val_losses, val_accuracies)

    # 保存模型
    torch.save(model.state_dict(), 'bert_text_encoder.pth')
    print("模型已保存为 'bert_text_encoder.pth'")
    #
    # # 示例：使用训练好的模型进行文本编码
    # print("\n示例：使用模型编码文本...")
    # model.eval()
    # device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    #
    # # 编码示例文本
    # sample_text = "This is a sample text for encoding"
    # encoding = tokenizer(
    #     sample_text,
    #     truncation=True,
    #     padding='max_length',
    #     max_length=128,
    #     return_tensors='pt'
    # )
    #
    # input_ids = encoding['input_ids'].to(device)
    # attention_mask = encoding['attention_mask'].to(device)
    #
    # # 获取32维embedding
    # embedding = model.encode_text(input_ids, attention_mask)
    # print(f"文本: '{sample_text}'")
    # print(f"32维Embedding形状: {embedding.shape}")
    # print(f"Embedding值 (前10维): {embedding[0][:10].tolist()}")


def encode():
    # train_df = pd.read_json('/home/xuhaoran/pycharm/Dual/data/final_data/train.jsonl', lines=True)
    test_df = pd.read_feather('/home/xuhaoran/pycharm/Dual/data/final_data/new_test.feather')

    model = BertTextEncoder()
    model.load_state_dict(torch.load('bert_text_encoder.pth'))
    model.eval()
    model.to(torch.device('cuda'))

    tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')

    # save_dir = Path('train_encode')
    # save_dir.mkdir(parents=True, exist_ok=True)
    # encode_df(save_dir, train_df, model, tokenizer)

    save_dir = Path('test_encode')
    save_dir.mkdir(parents=True, exist_ok=True)
    test_df = test_df.rename(columns={'cve_description': 'desc_cve', 'commit_message': 'commit_mess'})
    encode_df(save_dir, test_df, model, tokenizer)


def encode_df(save_dir, df, model, tokenizer, batch_size=32):
    desc_cve_code, unique_desc_cve = pd.factorize(df['desc_cve'])
    unique_desc_cve = list(unique_desc_cve)

    unique_desc_cve_emb = encode_text(unique_desc_cve, model, tokenizer, batch_size=batch_size)

    commit_mess = list(df['commit_mess'])
    commit_mess_emb = encode_text(commit_mess, model, tokenizer, batch_size=batch_size)

    np.save(save_dir / 'desc_cve_code.npy', desc_cve_code)
    np.save(save_dir / 'unique_desc_cve_emb.npy', unique_desc_cve_emb)
    np.save(save_dir / 'commit_mess_emb.npy', commit_mess_emb)

def encode_text(texts_to_encode, model, tokenizer, batch_size=32):
    all_embeddings = []
    for i in tqdm(range(0, len(texts_to_encode), batch_size), desc="编码批次"):
        batch_texts = texts_to_encode[i:i + batch_size]
        # Tokenize批次文本
        encodings = tokenizer(
            batch_texts,
            truncation=True,
            padding='max_length',
            max_length=128,
            return_tensors='pt'
        )

        input_ids = encodings['input_ids'].to('cuda')
        attention_mask = encodings['attention_mask'].to('cuda')

        # 获取embeddings
        embeddings = model.encode_text(input_ids, attention_mask)
        embeddings = embeddings.cpu().numpy().astype(np.float32)
        all_embeddings.extend(embeddings)

    all_embeddings = np.stack(all_embeddings)
    return all_embeddings

if __name__ == "__main__":
    os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7890'
    os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7890'
    encode()