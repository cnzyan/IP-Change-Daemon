import subprocess
import urllib3
 
http = urllib3.PoolManager()
 
def is_site_up(url):
    try:
        response = http.request('HEAD', url)
        return response.status == 200
    except urllib3.exceptions.MaxRetryError:
        return False
    
# 执行命令并获取输出
result = subprocess.run(
    ['pip', 'list'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# 打印输出
# print(result.stdout)
whllist = result.stdout.split('\n')
whllist1 = []
for whl in whllist:
    whl = whl.split(' ')[0].lower()
    whllist1.append(whl)
    # print(whl)

# 如果有错误，也可以打印错误信息
if result.stderr:
    print(result.stderr)

# 获取返回码
exit_code = result.returncode

lacklist = []

with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = f.readlines()
    requirements = [x.strip() for x in requirements]
    # print(requirements)
    for i in requirements:
        if i not in whllist1:
            # print(i)
            # print('not install')
            lacklist.append(i)
        else:
            # print(i)
            # print('install')
            pass
# print(lacklist)
pysources = ['https://pypi.tuna.tsinghua.edu.cn/simple',
             'https://mirrors.aliyun.com/pypi/simple/']
pys_url = pysources[0]
for pys in pysources:
    # print(pys)
    try:
        if is_site_up(pys):
            pys_url = pys
            break
    except:
        continue
if len(lacklist) == 0:
    print('all requirements are installed')
else:
    for i in lacklist:
        subprocess.run(['pip', 'install', i, '-i', pys_url])
        print(i + ' install success')
