import requests
import re

def get_repo_main_language(owner, repo, token=None):
    """
    获取GitHub仓库的主要编程语言

    Args:
        repo_url (str): GitHub仓库URL
        token (str, optional): GitHub访问令牌，提供更高的API请求限制

    Returns:
        dict: 包含主要语言和所有语言统计的字典
    """
    try:
        # 构建GitHub API URL
        api_url = f"https://api.github.com/repos/{owner}/{repo}/languages"

        # 设置请求头
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'GitHub-Language-Detector'
        }

        # 如果提供了token，添加到请求头
        if token:
            headers['Authorization'] = f'token {token}'

        # 发送API请求
        response = requests.get(api_url, headers=headers)

        # 检查响应状态
        if response.status_code == 200:
            languages = response.json()

            if not languages:
                return {
                    'main_language': None,
                    'all_languages': {},
                    'message': '该仓库没有检测到任何编程语言'
                }

            # 找到使用字节数最多的语言（主要语言）
            main_language = max(languages.items(), key=lambda x: x[1])

            # 计算每种语言的百分比
            total_bytes = sum(languages.values())
            languages_with_percentage = {}
            for lang, bytes_count in languages.items():
                percentage = (bytes_count / total_bytes) * 100
                languages_with_percentage[lang] = {
                    'bytes': bytes_count,
                    'percentage': round(percentage, 2)
                }

            return {
                'main_language': main_language[0],
                'main_language_bytes': main_language[1],
                'main_language_percentage': round((main_language[1] / total_bytes) * 100, 2),
                'all_languages': languages_with_percentage,
                'total_bytes': total_bytes
            }

        elif response.status_code == 404:
            return {
                'error': '仓库未找到',
                'message': '请检查仓库URL是否正确，或该仓库是否为私有仓库'
            }
        elif response.status_code == 403:
            return {
                'error': 'API请求限制',
                'message': '已达到GitHub API请求限制。请提供访问令牌或稍后重试'
            }
        else:
            return {
                'error': f'API请求失败 (状态码: {response.status_code})',
                'message': response.text
            }

    except ValueError as e:
        return {'error': 'URL解析错误', 'message': str(e)}
    except requests.exceptions.RequestException as e:
        return {'error': '网络请求错误', 'message': str(e)}
    except Exception as e:
        return {'error': '未知错误', 'message': str(e)}


def print_language_info(result):
    """格式化打印语言信息"""
    if 'error' in result:
        print(f"❌ 错误: {result['error']}")
        print(f"   {result['message']}")
        return

    if result['main_language'] is None:
        print(f"ℹ️  {result['message']}")
        return

    print(f"🎯 主要语言: {result['main_language']} ({result['main_language_percentage']}%)")
    print(f"📊 所有语言统计:")

    # 按百分比排序显示所有语言
    sorted_languages = sorted(
        result['all_languages'].items(),
        key=lambda x: x[1]['percentage'],
        reverse=True
    )

    for lang, info in sorted_languages:
        print(f"   {lang}: {info['percentage']}% ({info['bytes']:,} 字节)")

    print(f"📏 总代码量: {result['total_bytes']:,} 字节")


# 使用示例
if __name__ == "__main__":
    # # 示例1: 不使用访问令牌
    repo_url = "https://github.com/microsoft/vscode"
    # print("正在获取仓库语言信息...")
    # result = get_repo_main_language(repo_url)
    # print_language_info(result)
    #
    # print("\n" + "="*50 + "\n")

    # 示例2: 使用访问令牌（推荐）
    # 需要在GitHub设置中生成个人访问令牌
    token = "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"
    # result = get_repo_main_language(repo_url, token=token)
    # print_language_info(result)

    # 示例3: 批量检查多个仓库
    repos = [
        "python/cpython",
        "facebook/react",
        "golang/go"
    ]

    print("批量检查多个仓库:")
    for repo in repos:
        print(f"\n📁 仓库: {repo}")
        owner, repo = repo.split('/')
        result = get_repo_main_language(owner, repo, token=token)
        if 'main_language' in result and result['main_language']:
            print(f"   主要语言: {result['main_language']} ({result['main_language_percentage']}%)")
        else:
            print(f"   {result.get('message', result.get('error', '未知错误'))}")