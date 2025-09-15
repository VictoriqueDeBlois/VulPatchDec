import json
import logging
import os
from datetime import datetime


def load_json(path):
    with open(path, 'r', encoding='utf-8') as fp:
        data = json.load(fp)
    return data


def save_json(data, path):
    with open(path, 'w', encoding='utf-8') as fp:
        json.dump(data, fp, indent=4)


def send_email(receiver, title, text, smtp_server=None, mail_user=None, mail_pass=None, **kwargs):
    import smtplib
    import ssl
    from email.header import Header
    from email.mime.text import MIMEText

    if 'smtp_server' in kwargs:
        smtp_server = kwargs['smtp_server']
    if 'mail_host' in kwargs:
        smtp_server = kwargs['mail_host']
    if 'mail_user' in kwargs:
        mail_user = kwargs['mail_user']
    if 'mail_pass' in kwargs:
        mail_pass = kwargs['mail_pass']

    missing_params = []
    if mail_pass is None:
        missing_params.append('mail_pass')
    if mail_user is None:
        missing_params.append('mail_user')
    if smtp_server is None:
        missing_params.append('smtp_server')
    if len(missing_params) != 0:
        missing = ', '.join(missing_params)
        print(f'cannot find {missing}')
        return
    # 第三方 SMTP 服务
    sender = mail_user

    message = MIMEText(text, 'plain', 'utf-8')
    subject = title
    message['Subject'] = Header(subject, 'utf-8')
    message['from'] = sender
    message['to'] = receiver

    try:
        context = ssl.create_default_context()
        port = 465
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(mail_user, mail_pass)
            server.sendmail(sender, receiver, message.as_string())
        print("邮件发送成功")
    except smtplib.SMTPException as e:
        print(e)
        print("Error: 无法发送邮件")


def get_datetime():
    # 获取当前日期和时间
    current_datetime = datetime.now()
    # 将日期转换为字符串，可以使用不同的格式化选项
    full_datetime_string = current_datetime.strftime('%Y%m%d')  # 例如：20230822
    return full_datetime_string

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
