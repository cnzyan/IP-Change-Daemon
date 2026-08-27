import os, sys, time, re, smtplib, loguru, requests, pyquery, json, schedule
from concurrent.futures import ThreadPoolExecutor, as_completed
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import func_timeout
requests.packages.urllib3.disable_warnings()
# python -m venv ./.venv
# .\.venv\Scripts\Activate.ps1

# pyinstaller -F daemon_ip_chg_noemail.py

headers_raw = """
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding:gzip, deflate, br, zstd
Accept-Language:zh-CN,zh;q=0.9
Cache-Control:max-age=0
Priority:u=0, i
Sec-Ch-Ua:"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"
Sec-Ch-Ua-Mobile:?0
Sec-Ch-Ua-Platform:"Windows"
Sec-Fetch-Dest:document
Sec-Fetch-Mode:navigate
Sec-Fetch-Site:none
Sec-Fetch-User:?1
Upgrade-Insecure-Requests:1
User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
"""

def parse_headers(header_str):
    """解析 HTTP 请求头字符串为字典，正确处理含有 :// 和 :? 的值"""
    result = {}
    for line in header_str.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        if ':' in line:
            key, value = line.split(':', 1)
            result[key.strip()] = value.strip()
    return result

headers = parse_headers(headers_raw)

# IP 地址合法验证正则（匹配点分十进制）
IP_PATTERN = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')

REQUEST_TIMEOUT = 15


def is_valid_ip(ip_str):
    """验证IP地址是否合法"""
    ip_str = ip_str.strip()
    match = IP_PATTERN.match(ip_str)
    if not match:
        return False
    for i in range(1, 5):
        if int(match.group(i)) > 255:
            return False
    return True
def send_email(Subject,content, tomail, smtp_host, smtp_port, mail_user, mail_pass, sender_email, smtptype):  # 发送邮件-准备邮件内容
    # 设置登录及服务器信息
    # 设置email信息
    # 添加一个MIMEmultipart类，处理正文及附件
    message = MIMEMultipart()
    message['From'] = sender_email
    maillist = ""
    for mail in tomail:
        if maillist == "":
            maillist = maillist+mail
        else:
            maillist = maillist+","+mail
    message['To'] = maillist
    message['Cc'] = ""
    message['Bcc'] = ""
  
    # 设置html格式参数
    part1 = MIMEText(content, 'html', 'utf-8')
    # 添加一个附件
    message['Subject'] = Subject
    message.attach(part1)

    # message.attach(picture)
    return send_mail(message,  smtp_host, smtp_port,  mail_user, mail_pass, smtptype)


@func_timeout.func_set_timeout(90)
def send_mail(message,  smtp_host, smtp_port, user=None, passwd=None, security=None):  # 发送邮件
    '''
    Sends a message to a smtp server
    '''
    try:
        if security == 'SSL':
            s = smtplib.SMTP_SSL(smtp_host, smtp_port)
        else:
            s = smtplib.SMTP(smtp_host, smtp_port)
        # s.set_debuglevel(10)
        s.ehlo()

        if security == 'TLS':
            s.starttls()
            s.ehlo()

        if user:
            s.login(user, passwd)

        to_addr_list = []

        if message['To']:
            to_addr_list.append(message['To'])
        if message['Cc']:
            to_addr_list.append(message['Cc'])
        if message['Bcc']:
            to_addr_list.append(message['Bcc'])

        to_addr_list = ','.join(to_addr_list).split(',')

        s.sendmail(message['From'], to_addr_list, message.as_string())
        s.close()
        loguru.logger.info("邮件发送成功")
        return True
    except Exception as e:
        loguru.logger.error("邮件发送失败"+str(e))
        return False
def GetOuterIP(method):
    try:
        if method == "chinaz":
            url = r'https://ip.chinaz.com/'
            data = requests.get(url, headers=headers,
                                verify=False, timeout=REQUEST_TIMEOUT).content.decode('utf-8')
            d = pyquery.PyQuery(data)
            ip = str(d('#ip').text()).strip()
        elif method == "ipplus360":
            url = r'https://www.ipplus360.com/getIP'
            data = requests.get(url, verify=False, timeout=REQUEST_TIMEOUT).content.decode('utf-8')
            d = json.loads(data)
            ip = d['data'].strip()
        elif method == "ip138":
            url = r'https://2024.ip138.com/'
            data = requests.get(url, headers=headers,
                                verify=False, timeout=REQUEST_TIMEOUT).content.decode('utf-8')
            d = pyquery.PyQuery(data)
            ip = str(d('title').text()).strip()
            ip = ip.replace("您的IP地址是：", "").strip()
        else:
            loguru.logger.error("未知的获取IP地址方法")
            return None
    except Exception as e:
        loguru.logger.warning(f"获取IP失败({method}): {e}")
        return None

    if is_valid_ip(ip):
        loguru.logger.info(f"IP地址({method})：" + ip)
        return ip
    else:
        loguru.logger.warning(f"获取IP无效({method}): {ip}")
        return None
def send_email_ipchg():
    global last_ip, history_ip

    # 并行获取三个IP源
    ip_pool = []
    methods = ['chinaz', 'ipplus360', 'ip138']
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_method = {executor.submit(GetOuterIP, m): m for m in methods}
        for future in as_completed(future_to_method):
            result = future.result()
            if result is not None:
                ip_pool.append(result)

    # 去重
    ip_pool = list(set(ip_pool))

    # 过滤历史IP
    new_ips = [ip for ip in ip_pool if ip not in history_ip]

    if new_ips:
        for ip in new_ips:
            history_ip.append(ip)
            with open("history_ip.log", "a", encoding="utf-8") as f:
                f.write(ip + "\n")

    ip_pool_str = str(new_ips)
    if ip_pool_str == last_ip:
        loguru.logger.info("IP地址未变化，不发送邮件")
        return
    elif ip_pool_str == "[]":
        loguru.logger.info("IP地址为历史IP，不发送邮件")
        return
    else:
        last_ip = ip_pool_str
    print("NewIP:", ip_pool_str)

    contents = "IP地址变化为：" + ip_pool_str + "<br>请注意查看,历史IP地址为：" + str(history_ip)
    send_email(mail_title, contents, email_receivers, smtp_host,
               smtp_port, mail_user, mail_pass, sender_email, smtptype)

if __name__ == "__main__":
    last_ip = ''
    history_ip = []
    if not os.path.exists("history_ip.log"):
        with open("history_ip.log", "w", encoding="utf-8") as f:
            f.write("")
    with open("history_ip.log", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and is_valid_ip(line):
                history_ip.append(line)
    # 有序去重
    seen = set()
    unique_history = []
    for ip in history_ip:
        if ip not in seen:
            seen.add(ip)
            unique_history.append(ip)
    history_ip = unique_history
    if history_ip:
        with open("history_ip.log", "w", encoding="utf-8") as f:
            for ip in history_ip:
                f.write(ip + "\n")

    loguru.logger.add("daemon_ip_chg.log", rotation="1 day", retention="7 days", level="INFO", encoding="utf-8")
    send_email_ipchg()
    schedule.every(60).seconds.do(send_email_ipchg)

    while True:
        schedule.run_pending()
        time.sleep(10)