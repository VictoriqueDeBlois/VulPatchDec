import time
import logging
import re
import requests
import lxml
import pandas as pd
from tqdm import tqdm
from bs4 import BeautifulSoup, NavigableString, Tag

headers={
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36',
    # "Cookie": "" 
}



git_urls = ('git@github.com:FFmpeg/FFmpeg.git', 
           'git@github.com:torvalds/linux.git',
           'git@github.com:ImageMagick/ImageMagick.git',
           'git@github.com:php/php-src.git',
           'git@github.com:phpmyadmin/phpmyadmin.git',
           'git@github.com:moodle/moodle.git',
           'git@gitlab.com:wireshark/wireshark.git',
           'git@github.com:openssl/openssl.git',
           'git@github.com:jenkinsci/jenkins.git',
           'git@github.com:qemu/qemu.git')




if __name__ == '__main__':
    
    if not os.path.exists('../gitrepo'):
        os.makedirs('../gitrepo')
    repo_dir = '../gitrepo/'
    for git_url in tqdm(git_urls):
        git.Git(repo_dir).clone(git_url)


    df = pd.read_csv('../data/data.csv')
    df = df[['cve']]
    cve_list = df.cve.unique()
    
    ### get cve time
    result_list = []
    for cve in tqdm(cve_list):
        page = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name='+cve
        res = requests.get(url=page,  headers=headers)
        time.sleep(5) # Prevent frequent visits
        cvetime = re.search('<td><b>([0-9]{8})</b></td>', res.text).group(1)
        result_list.append((cve, cvetime))

    df = pd.DataFrame(result_list, columns = ['cve', 'cvetime'])

    ### get nvd info
    result_list = []
    for cve in tqdm(cve_list):
        page = 'https://nvd.nist.gov/vuln/detail/'+cve
        try:
            links = []
            cwe = ()
            soup = BeautifulSoup(res.text, 'lxml')
            tbody = soup.find(attrs={'data-testid': "vuln-hyperlinks-table"}).tbody
            for tr in tbody.children:
                if isinstance(tr, NavigableString): continue
                tds = tr.findAll('td')
                if 'Patch' in tds[1].text:
                    links.append(tds[0].a['href'])
            tbody = soup.find(attrs={'data-testid': "vuln-CWEs-table"}).tbody
            for tr in tbody.children:
                if isinstance(tr, NavigableString): continue
                tds = tr.findAll('td')
                cwe = (tds[0].text, tds[1].text)
        except Exception as e:
            logging.info(url + " ")
        time.sleep(5) # Prevent frequent visits
        result_list.append([cve, links, cwe])

    df2 = pd.DataFrame(result_list, columns=['cve', 'links', 'cwe'])
    df2 = df2.drop_duplicates(['cve']).reset_index(drop=True)

    df2['cwedesc'] = df2['cwe'].apply(lambda items:  items[1] if len(items) else '')
    df2['cwedesc'] = df2['cwedesc'].fillna('')
    df2['cwedesc'] = df2['cwedesc'].apply(lambda x: to_token(x))
        
    df3 = pd.read_csv("../data/cve_desc.csv")
    df3 = df.merge(df2[['cve', 'links', 'cwedesc']], how='left', on='cve').merge(df3, how='left', on='cve')
    df3.to_csv("../data/vuln_data.csv", index = False)