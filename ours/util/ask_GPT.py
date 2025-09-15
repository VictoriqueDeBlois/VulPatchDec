from datetime import time

import openai


def ask_gpt_turbo(prompt):
    # issue_id = "#2634"
    # print(cveid)
    max_retries = 5  # 设置最大重试次数
    retries = 0  # 记录当前重试次数

    openai.api_key = "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"
    rsp = openai.ChatCompletion.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "Vulnerability security analyst with knowledge of CVE, Github"},
            {"role": "user", "content": prompt}
        ]

    )
    res = rsp.get("choices")[0]["message"]["content"]
    print(res)
    return res
    # 解锁
    # except openai.error.ServiceUnavailableError as e:  # 捕获服务器不可用异常
    #     print(e)
    #     retries += 1  # 增加重试次数
    #     if retries > max_retries:  # 如果超过最大重试次数，抛出异常
    #         raise e
    #     wait = 2 ** retries  # 使用指数退避算法计算等待时间
    #     print(f"Retrying {retries}...")
    #     time.sleep(wait)  # 等待一段时间后重试
    # except openai.error.RateLimitError as e:  # 捕获速率限制异常
    #     print(e)
    #     retries += 1
    #     if retries > max_retries:
    #         raise e
    #     wait = e.headers.get("Retry-After", 60)  # 使用响应头中的 Retry-After 值作为等待时间
    #     print(f"Retrying {retries}...")
    #     time.sleep(wait)
