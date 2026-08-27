import threading
from functools import wraps
import os
import sys
import time
import re
import smtplib
import loguru
import requests
import pyquery
import json
import schedule
import configparser
import pystray
import tkinter as tk
from PIL import Image
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from queue import Queue
requests.packages.urllib3.disable_warnings()

# python -m venv ./.venv
# .\.venv\Scripts\Activate.ps1
# pyinstaller -F -w daemon_ip_chg.py -i ip.png -n 外网IP监控 --add-data="ip.png;."
# pyinstaller -F daemon_ip_chg.py

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


def new_thread(func):

    @wraps(func)
    def inner(*args, **kwargs):
        # print(f'函数的名字：{func.__name__}')
        # print(f'函数的位置参数：{args}')
        thread = threading.Thread(target=func, args=args, kwargs=kwargs)
        thread.daemon = True  # 设置为守护线程
        thread.start()

    return inner


def put_email_queue(message,  smtp_host, smtp_port,  mail_user, mail_pass, smtptype):
    """
    创建一个邮件队列
    """
    delay = 0
    email_queue.put((message, smtp_host, smtp_port,
                    mail_user, mail_pass, smtptype, delay))


@new_thread
def process_email_queue(email_queue):
    loguru.logger.info("邮件队列处理线程已启动")
    while 1 == 1:
        if email_queue.empty():
            # loguru.logger.info("邮件队列为空，等待新任务")
            time.sleep(1)
            continue
        msg, host, port, user, passwd, security, delay = email_queue.get()
        re_put = False
        if delay == 0:
            if send_mail(msg, host, port, user, passwd, security):
                pass
            else:
                delay = 60  # 如果发送失败，延迟60秒重试
                loguru.logger.error("邮件发送失败，延迟60秒重试")
                re_put = True
            time.sleep(0.1)
        else:
            time.sleep(1)
            delay -= 1
            if delay <= 0:
                delay = 0
            loguru.logger.info("邮件发送延迟，等待" + str(delay) + "秒")
            re_put = True
        if re_put:
            email_queue.put((msg, host, port, user, passwd, security, delay))


def send_email(Subject, content, tomail, smtp_host, smtp_port, mail_user, mail_pass, sender_email, smtptype):  # 发送邮件-准备邮件内容
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
    return put_email_queue(message,  smtp_host, smtp_port,  mail_user, mail_pass, smtptype)


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
        print("邮件发送成功")
        return True
    except Exception as e:
        loguru.logger.error("邮件发送失败"+str(e))
        print("邮件发送失败"+str(e))
        return False


def GetOuterIP(method):
    try:
        if method == "chinaz":
            url = r'https://ip.chinaz.com/'
            data = requests.get(url, headers=headers,
                                verify=False, timeout=REQUEST_TIMEOUT).content.decode('utf-8')
            d = pyquery.PyQuery(data)
            ip = str(d('input.text-black').attr('value')).strip()
        elif method == "ipplus360":
            url = r'https://www.ipplus360.com/getIP'
            data = requests.get(url, verify=False, timeout=REQUEST_TIMEOUT).content.decode('utf-8')
            d = json.loads(data)
            ip = d['data'].strip()
        elif method == "httpbin":
            url = r'https://httpbin.org/ip'
            data = requests.get(url, headers=headers,
                                verify=False, timeout=REQUEST_TIMEOUT).content.decode('utf-8')
            d = json.loads(data)
            ip = d['origin'].strip()
        elif method == "ip138":
            str_year = time.strftime("%Y", time.localtime())
            url = f'https://{str_year}.ip138.com/'
            data = requests.get(url, headers=headers,
                                verify=False, timeout=REQUEST_TIMEOUT).content.decode('utf-8')
            d = pyquery.PyQuery(data)
            ip = str(d('title').text()).strip()
            ip = ip.replace("您的IP地址是：", "").strip()
        elif method == "micromsg":
            url = r'https://qyapi.weixin.qq.com/cgi-bin/message/send'
            data = requests.get(url, headers=headers,
                                verify=False, timeout=REQUEST_TIMEOUT).content.decode('utf-8')
            reg = re.compile(r'from ip: (.*), more info')
            ip = reg.findall(data)
            ip = ip[0].strip()
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


def chk_ipchg():
    global last_ip, history_ip

    # 并行获取IP
    from concurrent.futures import ThreadPoolExecutor, as_completed
    methods = ['micromsg', 'chinaz', 'ipplus360', 'ip138']
    ip_pool = []
    num_get_fail = 0
    with ThreadPoolExecutor(max_workers=len(methods)) as executor:
        future_to_method = {executor.submit(GetOuterIP, m): m for m in methods}
        for future in as_completed(future_to_method):
            result = future.result()
            if result is not None:
                ip_pool.append(result)
            else:
                num_get_fail += 1

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
        print("IP地址未变化，不发送邮件")
        return
    elif ip_pool_str == "[]":
        loguru.logger.info("IP地址为历史IP，不发送邮件")
        print("IP地址为历史IP，不发送邮件")
        return
    else:
        last_ip = ip_pool_str
    print("NewIP:" + ip_pool_str)

    # 格式化IP输出
    ip_output = ";".join(new_ips)
    # 有序去重历史IP
    seen = set()
    unique_history = []
    for ip in history_ip:
        if ip not in seen:
            seen.add(ip)
            unique_history.append(ip)
    history_ip_output = ";".join(unique_history)

    contents = "IP地址变化为：" + ip_output + "<br>请注意查看,历史IP地址为：" + history_ip_output
    if chkIPchangeEmail == 1:  # 发送邮件
        send_email(mail_title + "IP地址改变", contents, email_receivers, smtp_host,
                   smtp_port, mail_user, mail_pass, sender_email, smtptype)


def get_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def chk_inet_access():
    global InetAccessLog, InetAccessMsg_waiting
    InetAccess = True
    timestr = get_time()
    try:
        url = r'https://www.baidu.com'
        requests.get(url, headers=headers,
                     verify=False, timeout=(30, 30))
        loguru.logger.info("网络访问正常" + timestr)
        print("网络访问正常" + timestr)
        InetAccessLog.append("网络访问正常" + timestr)
        InetAccess = True
    except Exception as e:
        loguru.logger.error("网络访问异常" + timestr + " " + str(e))
        print("网络访问异常" + timestr)
        InetAccessLog.append("网络访问异常" + timestr)
        InetAccess = False

    if len(InetAccessLog) > 60:
        InetAccessLog = InetAccessLog[-60:]
    with open("InetAccess.log", "w", encoding="utf-8") as f:
        for log in InetAccessLog:
            f.write(log + "\n")

    if InetAccess is False:
        InetAccessMsg_waiting = True
        return False
    else:
        if InetAccessMsg_waiting:
            InetAccessLogNew = []
            if InetAccessLog[-1].find("网络访问异常") == -1:
                last_fail = False
                for log in InetAccessLog:
                    if "网络访问异常" in log:
                        if last_fail == False:
                            InetAccessLogNew.append(log)
                            last_fail = True
                    if "网络访问正常" in log:
                        if last_fail == True:
                            InetAccessLogNew.append(log)
                            last_fail = False
                InetAccessMsg = "<br>".join(InetAccessLogNew)
                InetAccessMsg = InetAccessMsg.replace(
                    "网络访问异常", "<font color='red'>网络访问异常</font>")
                InetAccessMsg = InetAccessMsg.replace(
                    "网络访问正常", "<font color='green'>网络访问正常</font>")
                InetAccessMsg = "<h3>网络访问日志</h3><br>" + InetAccessMsg
                InetAccessLog = []
            if chkInetAccessEmail == 1:
                send_email(mail_title + "网络异常已恢复", InetAccessMsg, email_receivers, smtp_host,
                           smtp_port, mail_user, mail_pass, sender_email, smtptype)
            InetAccessMsg_waiting = False
        return True


def prepare_conf_file(configpath):  # 准备配置文件
    print(configpath)
    if not os.path.isfile(configpath):
        config.add_section("Email")
        config.set("Email", "smtp_host", r"smtp.qq.com")
        config.set("Email", "smtp_port", r"465")
        config.set("Email", "mail_user", r"111@qq.com")
        config.set("Email", "mail_pass", r"111")
        config.set("Email", "sender_email", r"111@qq.com")
        config.set("Email", "email_receivers", r"111@qq.com")
        config.set("Email", "smtptype", r"SSL")
        config.set("Email", "title", r"OutterIP")
        config.add_section("Config")
        config.set("Config", "chkIPchange", r"1")
        config.set("Config", "chkIPchangeEmail", r"1")
        config.set("Config", "chkIPchangeInterval", r"60")
        config.set("Config", "chkInetAccess", r"1")
        config.set("Config", "chkInetAccessEmail", r"1")
        config.set("Config", "chkInetAccessInterval", r"3600")
        with open(configpath, "w", encoding="utf-8") as f:
            config.write(f)


def get_conf_from_file(config_path, config_section, conf_list):  # 读取配置文件
    conf_default = {
        "secret_seed": "111",
        "wxmsg_touser": "111|111|111",
        "smtp_host": "",
        "smtp_port": "465",
        "mail_user": "",
        "mail_pass": "",
        "sender_email": "",
        "smtptype": "SSL",
        "email_receivers": "",
        "title": "OutterIP",
        "chkIPchange": "1",
        "chkIPchangeEmail": "1",
        "chkIPchangeInterval": "60",
        "chkInetAccess": "1",
        "chkInetAccessEmail": "1",
        "chkInetAccessInterval": "3600",
    }
    config.read(config_path, encoding="utf-8")
    conf_item_settings = []
    for conf_item in conf_list:
        try:
            conf_item_setting = config[config_section][conf_item]
            if conf_item == "piserver" or conf_item == "email_receivers":
                conf_item_setting = [item.strip() for item in conf_item_setting.split(",")]
        except Exception:
            conf_item_setting = conf_default[conf_item]
        print(str(conf_item) + ":" + str(conf_item_setting))
        conf_item_settings.append(conf_item_setting)
    if len(conf_list) > 1:
        return tuple(conf_item_settings)
    else:
        return conf_item_settings[0]


def get_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


if __name__ == "__main__":
    icon = ''
    config = configparser.ConfigParser()  # 类实例化

    # 定义文件路径
    configpath = r"./setup.ini"
    prepare_conf_file(configpath)
    (
        chkIPchange,
        chkIPchangeEmail,
        chkIPchangeInterval,
        chkInetAccess,
        chkInetAccessEmail,
        chkInetAccessInterval,
    ) = get_conf_from_file(
        configpath,
        "Config",
        [
            "chkIPchange",
            "chkIPchangeEmail",
            "chkIPchangeInterval",
            "chkInetAccess",
            "chkInetAccessEmail",
            "chkInetAccessInterval",
        ],
    )
    (
        email_receivers,
        smtp_host,
        smtp_port,
        mail_user,
        mail_pass,
        sender_email,
        smtptype,
        mail_title,
    ) = get_conf_from_file(
        configpath,
        "Email",
        [
            "email_receivers",
            "smtp_host",
            "smtp_port",
            "mail_user",
            "mail_pass",
            "sender_email",
            "smtptype",
            "title",
        ],
    )

    chkInetAccess = int(chkInetAccess.strip())
    chkInetAccessEmail = int(chkInetAccessEmail.strip())
    chkInetAccessInterval = int(chkInetAccessInterval.strip())
    chkIPchange = int(chkIPchange.strip())
    chkIPchangeEmail = int(chkIPchangeEmail.strip())
    chkIPchangeInterval = int(chkIPchangeInterval.strip())

    email_queue = Queue()
    process_email_queue(email_queue)

    last_ip = ''
    history_ip = []
    InetAccessLog = []
    InetAccessMsg_waiting = False
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

    loguru.logger.add(
        "daemon_ip_chg.log", rotation="1 day", retention="7 days", level="INFO", encoding="utf-8")
    if chk_inet_access() is True:
        chk_ipchg()
    if chkIPchange == 1:
        schedule.every(chkIPchangeInterval).seconds.do(chk_ipchg)
    if chkInetAccess == 1:
        schedule.every(chkInetAccessInterval).seconds.do(chk_inet_access)

    print(history_ip)
    while True:
        schedule.run_pending()
        time.sleep(10)
