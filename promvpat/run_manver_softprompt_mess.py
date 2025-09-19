import os
os.environ["CUDA_VISIBLE_DEVICES"] = "0"
os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7890'
os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7890'

import argparse
from openprompt.data_utils import InputExample
import json
from openprompt.prompts import ManualVerbalizer
from openprompt.plms import load_plm
from openprompt.prompts import SoftTemplate
from openprompt import PromptDataLoader
from openprompt import PromptForClassification
from transformers import AdamW

plm, tokenizer, model_config, WrapperClass = load_plm("t5", "google-t5/t5-base")
from tqdm import tqdm
import logging
import random
import numpy as np
logger = logging.getLogger(__name__)
import torch

def set_seed(seed=42):
    random.seed(seed)
    os.environ['PYHTONHASHSEED'] = str(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed(seed)
    torch.backends.cudnn.deterministic = True


def load_dataset(args):
    dataset = {}
    dataset['train'] = []
    i = 0
    with open(args.train_data_file) as f:
        for line in f:
            i += 1
            if i % 10000 == 0:
                print(i, flush=True)
            js = json.loads(line.strip())
            input_example = InputExample(text_a=js['desc_cve'].lower(), text_b=js['commit_mess'],
                                         label=int(js['label']), guid=js['idx'])
            dataset['train'].append(input_example)
    dataset['valid'] = []
    with open(args.eval_data_file) as f:
        for line in f:
            if i % 10000 == 0:
                print(i, flush=True)
            js = json.loads(line.strip())
            input_example = InputExample(text_a=js['desc_cve'].lower(), text_b=js['commit_mess'],
                                         label=int(js['label']), guid=js['idx'])
            dataset['valid'].append(input_example)
    dataset['test'] = []
    with open(args.test_data_file) as f:
        for line in f:
            if i % 10000 == 0:
                print(i, flush=True)
            js = json.loads(line.strip())
            input_example = InputExample(text_a=js['desc_cve'].lower(), text_b=js['commit_mess'],
                                         label=int(js['label']), guid=js['idx'])
            dataset['test'].append(input_example)
    return dataset


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train_data_file", default=None, type=str, required=True,
                        help="The input training data file.")
    parser.add_argument("--eval_data_file", default=None, type=str, required=True,
                        help="The input evaluation data file.")
    parser.add_argument("--test_data_file", default=None, type=str, required=True,
                        help="The input test data file.")
    parser.add_argument("--train_output_file", default=None, type=str, required=True,
                        help="The input test data file.")
    parser.add_argument("--eval_output_file", default=None, type=str, required=True,
                        help="The input test data file.")
    parser.add_argument("--test_output_file", default=None, type=str, required=True,
                        help="The input test data file.")
    parser.add_argument("--model_type", default="bert", type=str,
                        help="The model architecture to be fine-tuned.")
    parser.add_argument("--model_name_or_path", default=None, type=str,
                        help="The model checkpoint for weights initialization.")
    parser.add_argument("--train_batch_size", default=16, type=int,
                        help="Batch size per GPU/CPU for training.")
    parser.add_argument("--learning_rate", default=1e-5, type=float,
                        help="The initial learning rate for Adam.")
    parser.add_argument('--epoch', type=int, default=4,
                        help="random seed for initialization")
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
        # Distant debugging - see https://code.visualstudio.com/docs/python/debugging#_attach-to-a-local-script
        import ptvsd
        print("Waiting for debugger attach")
        ptvsd.enable_attach(address=(args.server_ip, args.server_port), redirect_output=True)
        ptvsd.wait_for_attach()

    # Setup CUDA, GPU & distributed training
    if args.local_rank == -1 or args.no_cuda:
        device = torch.device("cuda" if torch.cuda.is_available() and not args.no_cuda else "cpu")
        args.n_gpu = torch.cuda.device_count()
    else:  # Initializes the distributed backend which will take care of sychronizing nodes/GPUs
        torch.cuda.set_device(args.local_rank)
        device = torch.device("cuda", args.local_rank)
        torch.distributed.init_process_group(backend='nccl')
        args.n_gpu = 1
    args.device = device
    # Set seed
    set_seed(args.seed)
    # Load pretrained model and tokenizer
    if args.local_rank not in [-1, 0]:
        torch.distributed.barrier()  # Barrier to make sure only the first process in distributed training download model & vocab

    logging.basicConfig(format='%(asctime)s-%(levelname)s-%(name)s-%(message)s',
                        datefmt='%m/%d/%Y %H:%M:%S', level=logging.INFO)
    logger.info("Training/evaluation parameters %s", args)
    logger.info("logger begin dataset InputExample...")
    print('device', args.device, args.n_gpu)
    dataset = load_dataset(args)

    template_text = '{"placeholder":"text_a"} means {"placeholder":"text_b"}? Is it correct? {"mask"}.'
    mytemplate = SoftTemplate(model=plm, tokenizer=tokenizer, text=template_text, num_tokens=20)
    train_dataloader = PromptDataLoader(dataset=dataset["train"], template=mytemplate, tokenizer=tokenizer,
                                        tokenizer_wrapper_class=WrapperClass, max_seq_length=400, decoder_max_length=3,
                                        batch_size=args.train_batch_size, shuffle=True, teacher_forcing=False, predict_eos_token=False,
                                        truncate_method="head")

    myverbalizer = ManualVerbalizer(tokenizer, num_classes=2, label_words=[["yes"], ["no"]])
    use_cuda = True
    prompt_model = PromptForClassification(plm=plm, template=mytemplate, verbalizer=myverbalizer, freeze_plm=False)
    prompt_model.to(args.device)
    #prompt_model.cuda()
    #if args.local_rank == 0:
    #    torch.distributed.barrier()  # End of barrier to make sure only the first process in distributed training download model & vocab
    # device_map (Dict[int, list], optional, defaults to None) — A dictionary that maps attention modules to devices. 
    # Note that the embedding module and LMHead are always automatically mapped to the first device (for esoteric reasons). 
    # That means that the first device should have fewer attention modules mapped to it than other devices.
    # mt5-small: 6
    # mt5-base: 12
    # mt5-large: 24
    if use_cuda and args.n_gpu>1:
        device_map = {
                1: [0,1,2,3,4,5,6,7],
                2: [8,9,10,11],
                }
        print("using multiple gpus\n", flush=True)
        prompt_model.cuda()
        #prompt_model.parallelize()
        #prompt_model.parallelize(device_map)
        #prompt_model = torch.nn.DataParallel(prompt_model)
    ## Distributed training (should be after apex fp16 initialization)
    #if args.local_rank != -1:
    #    prompt_model = torch.nn.parallel.DistributedDataParallel(prompt_model, device_ids=[args.local_rank],
    #                                                             output_device=args.local_rank,
    #                                                             find_unused_parameters=True)

    # Now the training is standard
    loss_func = torch.nn.CrossEntropyLoss()
    no_decay = ['bias', 'LayerNorm.weight']
    # it's always good practice to set no decay to biase and LayerNorm parameters
    optimizer_grouped_parameters = [
        {'params': [p for n, p in prompt_model.named_parameters() if not any(nd in n for nd in no_decay)], 'weight_decay': 0.01},
        {'params': [p for n, p in prompt_model.named_parameters() if any(nd in n for nd in no_decay)], 'weight_decay': 0.0}
    ]
    optimizer = AdamW(optimizer_grouped_parameters, lr=args.learning_rate)
    logger.info("logger begin training...")
    prompt_model.zero_grad()
    for epoch in range(args.epoch):
        bar = tqdm(train_dataloader, total=len(train_dataloader))
        stop_num = 0
        tot_loss = 0
        best_acc = 0.0
        alllabels = []
        allpreds = []
        allidxs = []
        allprobs = []
        output = []
        for step, inputs in enumerate(bar):
            if use_cuda:
                inputs = inputs.to(args.device)
            prompt_model.train()
            logits = prompt_model(inputs)
            labels = inputs['label']
            idxs = inputs['guid']
            loss = loss_func(logits, labels)
            loss.backward()
            tot_loss += loss.item()
            optimizer.step()
            optimizer.zero_grad()
            if step %200 ==1:
                print("Epoch {}, average loss: {}".format(epoch, tot_loss/(step+1)), flush=True)
            alllabels.extend(labels.cpu().tolist())
            allpreds.extend(torch.argmax(logits, dim=-1).cpu().tolist())
            probability = logits[:, 1].cpu().tolist()
            allprobs.extend(probability)
            allidxs.extend(idxs.cpu().tolist())
        acc = sum([int(i == j) for i, j in zip(allpreds, alllabels)]) / len(allpreds)
        if acc > best_acc:
            best_acc = acc
        if best_acc <= acc:
            stop_num += 1
        if stop_num == 2 or epoch==0:
            for i in range(len(allprobs)):
                js = dict()
                js['idx'] = allidxs[i]
                js['label'] = alllabels[i]
                js['logits'] = allprobs[i]
                output.append(js)
            with open(args.train_output_file, "w") as f:
                json.dump(output, f)
                f.close()
            break

    torch.save(prompt_model, '../model/run_manver_softprompt_mess.pth')

    # Evaluate
    logger.info("logger begin Evaluating...")
    validation_dataloader = PromptDataLoader(dataset=dataset["valid"], template=mytemplate, tokenizer=tokenizer,
                                             tokenizer_wrapper_class=WrapperClass, max_seq_length=512, decoder_max_length=3,
                                             batch_size=args.train_batch_size, shuffle=False, teacher_forcing=False, predict_eos_token=False,
                                             truncate_method="head")
    allpreds = []
    alllabels = []
    allidxs = []
    output = []
    allprobs = []
    prompt_model.eval()
    bar = tqdm(validation_dataloader, total=len(validation_dataloader))
    for step, inputs in enumerate(bar):
        if use_cuda:
            inputs = inputs.to(args.device)
        with torch.no_grad():
            logits = prompt_model(inputs)
            labels = inputs['label']
            idxs = inputs['guid']
            alllabels.extend(labels.cpu().tolist())
            allpreds.extend(torch.argmax(logits, dim=-1).cpu().tolist())
            probability = logits[:, 1].cpu().tolist()
            allprobs.extend(probability)
            allidxs.extend(idxs.cpu().tolist())
    for i in range(len(allprobs)):
        js = dict()
        js['idx'] = allidxs[i]
        js['label'] = alllabels[i]
        js['logits'] = allprobs[i]
        output.append(js)
    with open(args.eval_output_file, "w") as f:
        json.dump(output, f)
        f.close()
    acc = sum([int(i == j) for i, j in zip(allpreds, alllabels)])/len(allpreds)
    print('the acc in validation:', acc, flush=True)

    # Test
    logger.info("logger begin Testing...")
    test_dataloader = PromptDataLoader(dataset=dataset["test"], template=mytemplate, tokenizer=tokenizer,
                                       tokenizer_wrapper_class=WrapperClass, max_seq_length=512, decoder_max_length=3,
                                       batch_size=args.train_batch_size, shuffle=False, teacher_forcing=False, predict_eos_token=False,
                                       truncate_method="head")
    allpreds = []
    alllabels = []
    allidxs = []
    output = []
    allprobs = []
    bar = tqdm(test_dataloader, total=len(test_dataloader))
    prompt_model.eval()
    for step, inputs in enumerate(bar):
        if use_cuda:
            inputs = inputs.to(args.device)
        with torch.no_grad():
            logits = prompt_model(inputs)
            labels = inputs['label']
            idxs = inputs['guid']
            alllabels.extend(labels.cpu().tolist())
            allpreds.extend(torch.argmax(logits, dim=-1).cpu().tolist())
            probability = logits[:, 1].cpu().tolist()
            allprobs.extend(probability)
            allidxs.extend(idxs.cpu().tolist())
    for i in range(len(allpreds)):
        js = dict()
        js['idx'] = allidxs[i]
        js['label'] = alllabels[i]
        js['logits'] = allprobs[i]
        output.append(js)
    with open(args.test_output_file, "w") as f:
        json.dump(output, f)
        f.close()
    acc = sum([int(i == j) for i, j in zip(allpreds, alllabels)])/len(allpreds)
    print('the acc in test:', acc, flush=True)
    logger.info("logger finish...")

def model_test(args, dataset, mytemplate, use_cuda):
    prompt_model = torch.load('./model/run_manver_softprompt_mess.pth')

    if use_cuda:
        prompt_model = prompt_model.cuda()

    # Test
    logger.info("logger begin Testing...")
    test_dataloader = PromptDataLoader(dataset=dataset["test"], template=mytemplate, tokenizer=tokenizer,
                                       tokenizer_wrapper_class=WrapperClass, max_seq_length=512, decoder_max_length=3,
                                       batch_size=args.train_batch_size, shuffle=False, teacher_forcing=False, predict_eos_token=False,
                                       truncate_method="head")
    allpreds = []
    alllabels = []
    allidxs = []
    output = []
    allprobs = []
    bar = tqdm(test_dataloader, total=len(test_dataloader))
    prompt_model.eval()
    for step, inputs in enumerate(bar):
        if use_cuda:
            inputs = inputs.to(args.device)
        with torch.no_grad():
            logits = prompt_model(inputs)
            labels = inputs['label']
            idxs = inputs['guid']
            alllabels.extend(labels.cpu().tolist())
            allpreds.extend(torch.argmax(logits, dim=-1).cpu().tolist())
            probability = logits[:, 1].cpu().tolist()
            allprobs.extend(probability)
            allidxs.extend(idxs.cpu().tolist())
    for i in range(len(allpreds)):
        js = dict()
        js['idx'] = allidxs[i]
        js['label'] = alllabels[i]
        js['logits'] = allprobs[i]
        output.append(js)
    with open(args.test_output_file, "w") as f:
        json.dump(output, f)
        f.close()
    acc = sum([int(i == j) for i, j in zip(allpreds, alllabels)])/len(allpreds)
    print('the acc in test:', acc, flush=True)
    logger.info("logger finish...")


def pre_process():
    parser = argparse.ArgumentParser()
    parser.add_argument("--train_data_file", default=None, type=str, required=True,
                        help="The input training data file.")
    parser.add_argument("--eval_data_file", default=None, type=str, required=True,
                        help="The input evaluation data file.")
    parser.add_argument("--test_data_file", default=None, type=str, required=True,
                        help="The input test data file.")
    parser.add_argument("--train_output_file", default=None, type=str, required=True,
                        help="The input test data file.")
    parser.add_argument("--eval_output_file", default=None, type=str, required=True,
                        help="The input test data file.")
    parser.add_argument("--test_output_file", default=None, type=str, required=True,
                        help="The input test data file.")
    parser.add_argument("--model_type", default="bert", type=str,
                        help="The model architecture to be fine-tuned.")
    parser.add_argument("--model_name_or_path", default=None, type=str,
                        help="The model checkpoint for weights initialization.")
    parser.add_argument("--train_batch_size", default=16, type=int,
                        help="Batch size per GPU/CPU for training.")
    parser.add_argument("--learning_rate", default=1e-5, type=float,
                        help="The initial learning rate for Adam.")
    parser.add_argument('--epoch', type=int, default=4,
                        help="random seed for initialization")
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
        # Distant debugging - see https://code.visualstudio.com/docs/python/debugging#_attach-to-a-local-script
        import ptvsd
        print("Waiting for debugger attach")
        ptvsd.enable_attach(address=(args.server_ip, args.server_port), redirect_output=True)
        ptvsd.wait_for_attach()

    # Setup CUDA, GPU & distributed training
    if args.local_rank == -1 or args.no_cuda:
        device = torch.device("cuda" if torch.cuda.is_available() and not args.no_cuda else "cpu")
        args.n_gpu = torch.cuda.device_count()
    else:  # Initializes the distributed backend which will take care of sychronizing nodes/GPUs
        torch.cuda.set_device(args.local_rank)
        device = torch.device("cuda", args.local_rank)
        torch.distributed.init_process_group(backend='nccl')
        args.n_gpu = 1
    args.device = device
    # Set seed
    set_seed(args.seed)
    # Load pretrained model and tokenizer
    if args.local_rank not in [-1, 0]:
        torch.distributed.barrier()  # Barrier to make sure only the first process in distributed training download model & vocab

    logging.basicConfig(format='%(asctime)s-%(levelname)s-%(name)s-%(message)s',
                        datefmt='%m/%d/%Y %H:%M:%S', level=logging.INFO)
    logger.info("Training/evaluation parameters %s", args)
    logger.info("logger begin dataset InputExample...")
    print('device', args.device, args.n_gpu)
    dataset = load_dataset(args)

    template_text = '{"placeholder":"text_a"} means {"placeholder":"text_b"}? Is it correct? {"mask"}.'
    mytemplate = SoftTemplate(model=plm, tokenizer=tokenizer, text=template_text, num_tokens=20)
    use_cuda = True

    return args, dataset, mytemplate, use_cuda


if __name__ == "__main__":
    # args, dataset, mytemplate, use_cuda = pre_process()
    # model_test(args, dataset, mytemplate, use_cuda)
    main()