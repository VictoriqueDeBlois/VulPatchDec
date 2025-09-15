import argparse
import os
import random
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from openprompt import PromptDataLoader
from openprompt import PromptForClassification
from openprompt.data_utils import InputExample
from openprompt.plms import load_plm
from openprompt.prompts import ManualVerbalizer
from openprompt.prompts import SoftTemplate
from sklearn.metrics import f1_score
from tqdm import tqdm
from transformers import AdamW

from util import setup_logging, load_pkl, save_pkl

logger = setup_logging('commit_soft_prompt', True)

def set_seed(seed=42):
    random.seed(seed)
    os.environ['PYHTONHASHSEED'] = str(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed(seed)
    torch.backends.cudnn.deterministic = True


def _load_data(df: pd.DataFrame):
    input_examples = []
    for index, row in tqdm(df.iterrows(), total=len(df)):
        cve_description = row['cve_description']
        commit_message = row['commit_message']
        label = row['label']
        idx = row['idx']
        input_example = InputExample(text_a=cve_description.lower(), text_b=commit_message.lower(),
                                     label=int(label), guid=int(idx))
        input_examples.append(input_example)
    return input_examples

def load_dataset(args):
    """加载训练、验证和测试数据集"""
    dataset = {}
    df = pd.read_json(args.train_data_file, lines=True)
    df = df.rename(columns={'desc_cve': 'cve_description', 'commit_mess': 'commit_message'})
    dataset['train'] = _load_data(df)
    df = pd.read_json(args.eval_data_file, lines=True)
    df = df.rename(columns={'desc_cve': 'cve_description', 'commit_mess': 'commit_message'})
    dataset['valid'] = _load_data(df)
    df = pd.read_feather(args.test_data_file)
    dataset['test'] = _load_data(df)

    return dataset


def train_one_epoch(prompt_model, train_dataloader, optimizer, loss_func, device, epoch, use_cuda=True):
    """训练一个epoch"""
    prompt_model.train()
    bar = tqdm(train_dataloader, total=len(train_dataloader))
    tot_loss = 0
    alllabels = []
    allpreds = []
    allidxs = []
    allprobs = []

    for step, inputs in enumerate(bar):
        if use_cuda:
            inputs = inputs.to(device)

        logits = prompt_model(inputs)
        labels = inputs['label']
        idxs = inputs['guid']
        loss = loss_func(logits, labels)

        loss.backward()
        tot_loss += loss.item()
        optimizer.step()
        optimizer.zero_grad()

        if step % 200 == 1:
            logger.info(f"Epoch {epoch}, average loss: {tot_loss / (step + 1)}")

        alllabels.extend(labels.cpu().tolist())
        allpreds.extend(torch.argmax(logits, dim=-1).cpu().tolist())
        probability = logits[:, 1].cpu().tolist()
        allprobs.extend(probability)
        allidxs.extend(idxs.cpu().tolist())

    # 计算训练准确率
    train_acc = f1_score(alllabels, allpreds)
    avg_loss = tot_loss / len(train_dataloader)

    return train_acc, avg_loss, alllabels, allpreds, allidxs, allprobs


def validate(prompt_model, validation_dataloader, device, use_cuda=True):
    """验证函数"""
    prompt_model.eval()
    allpreds = []
    alllabels = []
    allidxs = []
    allprobs = []

    bar = tqdm(validation_dataloader, total=len(validation_dataloader), desc="Validating")

    for step, inputs in enumerate(bar):
        if use_cuda:
            inputs = inputs.to(device)

        with torch.no_grad():
            logits = prompt_model(inputs)
            labels = inputs['label']
            idxs = inputs['guid']

            alllabels.extend(labels.cpu().tolist())
            allpreds.extend(torch.argmax(logits, dim=-1).cpu().tolist())
            probability = logits[:, 1].cpu().tolist()
            allprobs.extend(probability)
            allidxs.extend(idxs.cpu().tolist())

    # 计算验证准确率
    val_acc = f1_score(alllabels, allpreds)

    return val_acc, alllabels, allpreds, allidxs, allprobs


def test(prompt_model, test_dataloader, device, use_cuda=True):
    """测试函数"""
    prompt_model.eval()
    allpreds = []
    alllabels = []
    allidxs = []
    allprobs = []

    bar = tqdm(test_dataloader, total=len(test_dataloader), desc="Testing")

    for step, inputs in enumerate(bar):
        if use_cuda:
            inputs = inputs.to(device)

        with torch.no_grad():
            logits = prompt_model(inputs)
            labels = inputs['label']
            idxs = inputs['guid']

            alllabels.extend(labels.cpu().tolist())
            allpreds.extend(torch.argmax(logits, dim=-1).cpu().tolist())
            probability = logits[:, 1].cpu().tolist()
            allprobs.extend(probability)
            allidxs.extend(idxs.cpu().tolist())

    # 计算测试准确率
    test_acc = f1_score(alllabels, allpreds)

    return test_acc, alllabels, allpreds, allidxs, allprobs


def save_results(output_file, labels, preds, idxs, probs):
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    """保存结果到文件"""
    pd.DataFrame({
        'idx': idxs,
        'logit': probs,
        'predict': preds,
        'label': labels
    }).to_csv(output_file, index=False)


def train_with_early_stopping(prompt_model, train_dataloader, validation_dataloader,
                              optimizer, loss_func, device, args, use_cuda=True,
                              patience=3, min_delta=0.001):
    """带早停策略的训练函数"""
    best_val_acc = 0.0
    patience_counter = 0
    best_model_state = None

    logger.info("开始训练...")
    logger.info(f"训练参数: epochs={args.epoch}, patience={patience}, min_delta={min_delta}")

    for epoch in range(args.epoch):
        logger.info(f"\n=== Epoch {epoch + 1}/{args.epoch} ===")

        # 训练一个epoch
        train_acc, train_loss, train_labels, train_preds, train_idxs, train_probs = train_one_epoch(
            prompt_model, train_dataloader, optimizer, loss_func, device, epoch, use_cuda)
        logger.info(f"Epoch {epoch + 1} - Train Acc: {train_acc:.4f}, Train Loss: {train_loss:.4f}")
        
        # 验证
        val_acc, val_labels, val_preds, val_idxs, val_probs = validate(
            prompt_model, validation_dataloader, device, use_cuda)
        logger.info(f"Epoch {epoch + 1} - Val Acc: {val_acc:.4f}")

        # 早停判断
        if val_acc > best_val_acc + min_delta:
            best_val_acc = val_acc
            patience_counter = 0
            # 保存最佳模型状态
            best_model_state = prompt_model.state_dict().copy()
            logger.info(f"新的最佳验证准确率: {best_val_acc:.4f}")
            torch.save(prompt_model.state_dict(), f"../model/commit_soft_prompt/best_checkpoint.pth")
        else:
            patience_counter += 1
            logger.info(f"验证准确率未改善，patience计数: {patience_counter}/{patience}")

        # 如果达到patience限制，提前停止
        if patience_counter >= patience:
            logger.info(f"\n早停触发！在epoch {epoch + 1}停止训练")
            logger.info(f"最佳验证准确率: {best_val_acc:.4f}")
            break

    # 恢复最佳模型状态
    if best_model_state is not None:
        prompt_model.load_state_dict(best_model_state)
        logger.info("已恢复到最佳模型状态")

    return best_val_acc


def setup_model_and_dataloaders(args):
    """设置模型和数据加载器"""
    plm, tokenizer, model_config, WrapperClass = load_plm("t5", "google-t5/t5-base")
    # 设置模板和数据加载器
    template_text = '{"placeholder":"text_a"} means {"placeholder":"text_b"}? Is it correct? {"mask"}.'
    mytemplate = SoftTemplate(model=plm, tokenizer=tokenizer, text=template_text, num_tokens=20)

    out_dir = Path('./commit_soft_prompt_temp_data')
    train_temp = out_dir / 'train_dataloader.pkl'
    val_temp = out_dir / 'val_dataloader.pkl'
    test_temp = out_dir / 'test_dataloader.pkl'

    dataset = {}
    if test_temp.exists():
        train_dataloader = load_pkl(train_temp)
    else:
        df = pd.read_json(args.train_data_file, lines=True)
        df = df.rename(columns={'desc_cve': 'cve_description', 'commit_mess': 'commit_message'})
        dataset['train'] = _load_data(df)
        train_dataloader = PromptDataLoader(
            dataset=dataset["train"], template=mytemplate, tokenizer=tokenizer,
            tokenizer_wrapper_class=WrapperClass, max_seq_length=512, decoder_max_length=3,
            batch_size=args.train_batch_size, shuffle=True, teacher_forcing=False,
            predict_eos_token=False, truncate_method="head")
        save_pkl(train_dataloader, train_temp)

    if val_temp.exists():
        validation_dataloader = load_pkl(val_temp)
    else:
        df = pd.read_json(args.eval_data_file, lines=True)
        df = df.rename(columns={'desc_cve': 'cve_description', 'commit_mess': 'commit_message'})
        dataset['valid'] = _load_data(df)
        validation_dataloader = PromptDataLoader(
            dataset=dataset["valid"], template=mytemplate, tokenizer=tokenizer,
            tokenizer_wrapper_class=WrapperClass, max_seq_length=512, decoder_max_length=3,
            batch_size=args.train_batch_size, shuffle=False, teacher_forcing=False,
            predict_eos_token=False, truncate_method="head")
        save_pkl(validation_dataloader, val_temp)

    if test_temp.exists():
        test_dataloader = load_pkl(test_temp)
    else:
        df = pd.read_feather(args.test_data_file)
        dataset['test'] = _load_data(df)
        test_dataloader = PromptDataLoader(
            dataset=dataset["test"], template=mytemplate, tokenizer=tokenizer,
            tokenizer_wrapper_class=WrapperClass, max_seq_length=512, decoder_max_length=3,
            batch_size=args.train_batch_size, shuffle=False, teacher_forcing=False,
            predict_eos_token=False, truncate_method="head")
        save_pkl(test_dataloader, test_temp)

    # 设置模型
    myverbalizer = ManualVerbalizer(tokenizer, num_classes=2, label_words=[["yes"], ["no"]])
    prompt_model = PromptForClassification(plm=plm, template=mytemplate, verbalizer=myverbalizer, freeze_plm=False)
    prompt_model.to(args.device)

    # 多GPU设置
    use_cuda = True
    if use_cuda and args.n_gpu > 1:
        device_map = {
            1: [0, 1, 2, 3, 4, 5, 6, 7],
            2: [8, 9, 10, 11],
        }
        logger.info("using multiple gpus\n")
        prompt_model.cuda()

    return prompt_model, train_dataloader, validation_dataloader, test_dataloader


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train_data_file", default=None, type=str, required=True,
                        help="The input training data file.")
    parser.add_argument("--eval_data_file", default=None, type=str, required=True,
                        help="The input evaluation data file.")
    parser.add_argument("--test_data_file", default=None, type=str, required=True,
                        help="The input test data file.")
    parser.add_argument("--train_output_file", default=None, type=str, required=True,
                        help="The output training results file.")
    parser.add_argument("--eval_output_file", default=None, type=str, required=True,
                        help="The output evaluation results file.")
    parser.add_argument("--test_output_file", default=None, type=str, required=True,
                        help="The output test results file.")
    parser.add_argument("--model_type", default="bert", type=str,
                        help="The model architecture to be fine-tuned.")
    parser.add_argument("--model_name_or_path", default=None, type=str,
                        help="The model checkpoint for weights initialization.")
    parser.add_argument("--train_batch_size", default=16, type=int,
                        help="Batch size per GPU/CPU for training.")
    parser.add_argument("--learning_rate", default=1e-5, type=float,
                        help="The initial learning rate for Adam.")
    parser.add_argument('--epoch', type=int, default=4,
                        help="Maximum number of epochs")
    parser.add_argument('--patience', type=int, default=3,
                        help="Early stopping patience")
    parser.add_argument('--min_delta', type=float, default=0.001,
                        help="Minimum improvement for early stopping")
    parser.add_argument('--seed', type=int, default=42,
                        help="random seed for initialization")
    parser.add_argument("--no_cuda", action='store_true', help="Avoid using CUDA when available")
    parser.add_argument("--local_rank", type=int, default=-1,
                        help="For distributed training: local_rank")
    parser.add_argument('--server_ip', type=str, default='', help="For distant debugging.")
    parser.add_argument('--server_port', type=str, default='', help="For distant debugging.")
    args = parser.parse_args()

    # Setup distant debugging if needed
    if args.server_ip and args.server_port:
        import ptvsd
        logger.info("Waiting for debugger attach")
        ptvsd.enable_attach(address=(args.server_ip, args.server_port), redirect_output=True)
        ptvsd.wait_for_attach()

    # Setup CUDA, GPU & distributed training
    if args.local_rank == -1 or args.no_cuda:
        device = torch.device("cuda" if torch.cuda.is_available() and not args.no_cuda else "cpu")
        args.n_gpu = torch.cuda.device_count()
    else:
        torch.cuda.set_device(args.local_rank)
        device = torch.device("cuda", args.local_rank)
        torch.distributed.init_process_group(backend='nccl')
        args.n_gpu = 1
    args.device = device

    # Set seed
    set_seed(args.seed)

    logger.info(f"Training/evaluation parameters {args}")
    logger.info("开始加载数据集...")
    logger.info(f'device: {args.device}, {args.n_gpu}')
    Path('../model/commit_soft_prompt').mkdir(parents=True, exist_ok=True)
    # # 加载数据集
    # dataset = load_dataset(args)

    # 设置模型和数据加载器
    prompt_model, train_dataloader, validation_dataloader, test_dataloader = setup_model_and_dataloaders(args)

    # 设置优化器
    loss_func = torch.nn.CrossEntropyLoss()
    no_decay = ['bias', 'LayerNorm.weight']
    optimizer_grouped_parameters = [
        {'params': [p for n, p in prompt_model.named_parameters() if not any(nd in n for nd in no_decay)],
         'weight_decay': 0.01},
        {'params': [p for n, p in prompt_model.named_parameters() if any(nd in n for nd in no_decay)],
         'weight_decay': 0.0}
    ]
    optimizer = AdamW(optimizer_grouped_parameters, lr=args.learning_rate)

    # 训练（带早停策略）
    best_val_acc = train_with_early_stopping(
        prompt_model, train_dataloader, validation_dataloader,
        optimizer, loss_func, args.device, args, use_cuda=True,
        patience=args.patience, min_delta=args.min_delta)

    # 保存模型
    torch.save(prompt_model, '../model/commit_soft_prompt/commit_soft_prompt.pth')
    logger.info(f"模型已保存，最佳验证准确率: {best_val_acc:.4f}")

    # 最终测试
    logger.info("开始最终测试...")
    train_acc, train_labels, train_preds, train_idxs, train_probs = test(
        prompt_model, train_dataloader, args.device, use_cuda=True)
    val_acc, val_labels, val_preds, val_idxs, val_probs = test(
        prompt_model, train_dataloader, args.device, use_cuda=True)
    test_acc, test_labels, test_preds, test_idxs, test_probs = test(
        prompt_model, test_dataloader, args.device, use_cuda=True)

    # 保存测试结果
    save_results(args.train_output_file, train_labels, train_preds, train_idxs, train_probs)
    save_results(args.eval_output_file, val_labels, val_preds, val_idxs, val_probs)
    save_results(args.test_output_file, test_labels, test_preds, test_idxs, test_probs)

    logger.info(f'最终训练准确率: {train_acc:.4f}')
    logger.info(f'最终验证准确率: {val_acc:.4f}')
    logger.info(f'最终测试准确率: {test_acc:.4f}')
    logger.info("训练完成！")


if __name__ == "__main__":
    os.environ["CUDA_VISIBLE_DEVICES"] = "0"
    os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7890'
    os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7890'
    main()
