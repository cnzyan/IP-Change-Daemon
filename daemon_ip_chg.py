import threading
from functools import wraps
import os
import sys
import time
import re
import smtplib
import func_timeout
import loguru
import requests
import pyquery
import json
import schedule
import chardet
import configparser
import pystray
from PIL import Image
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
requests.packages.urllib3.disable_warnings()

# python -m venv ./.venv
# .\.venv\Scripts\Activate.ps1
# pyinstaller -F -w daemon_ip_chg.py -i ip.png -n 外网IP监控 --add-data="ip.png;."
# pyinstaller -F daemon_ip_chg.py

headers = """
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
# 去除参数头尾的空格并按换行符分割
headers = headers.strip().split('\n')

# 使用字典生成式将参数切片重组，并去掉空格，处理带协议头中的://
headers = {x.split(':')[0].strip(): (
    "".join(x.split(':')[1:])).strip().replace('//', "://") for x in headers}


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
        console_print("邮件发送成功")
        return True
    except Exception as e:
        loguru.logger.error("邮件发送失败"+str(e))
        console_print("邮件发送失败"+str(e))
        return False


def GetOuterIP(method):
    if method == "chinaz":
        try:
            url = r'https://ip.chinaz.com/'
            data = requests.get(url, headers=headers,
                                verify=False).content.decode('utf-8')
            # print(data)
            d = pyquery.PyQuery(data)
            ip = str(d('#ip').text())
            # print(ip)
        except:
            ip = "无法获取，可能是网站改版，请手动访问 https://ip.chinaz.com"
        loguru.logger.info("IP地址："+ip+"")
        return ip
    elif method == "ipplus360":
        try:
            url = r'https://www.ipplus360.com/getIP'
            data = requests.get(url, verify=False).content.decode('utf-8')
            # print(data)
            # {"success":true,"code":200,"msg":"获取用户端IP成功","data":""}
            d = json.loads(data)
            ip = d['data']
            # print(ip)
            pass
        except:
            ip = "无法获取，可能是网站改版，请手动访问 https://www.ipplus360.com"
        loguru.logger.info("IP地址："+ip+"")
        return ip
    elif method == "ip138":
        try:
            url = r'https://2024.ip138.com/'
            data = requests.get(url, headers=headers,
                                verify=False).content.decode('utf-8')
            # print(data)
            d = pyquery.PyQuery(data)
            ip = str(d('title').text())
            ip = ip.replace("您的IP地址是：", "")
            # print(ip)
        except:
            ip = "无法获取，可能是网站改版，请手动访问 https://2024.ip138.com/"
        loguru.logger.info("IP地址："+ip+"")
        return ip
    else:
        loguru.logger.error("未知的获取IP地址方法")
        ip = "未知的获取IP地址方法"
        return ip


def chk_ipchg():
    global last_ip, history_ip
    # 设置登录及服务器信息
    ip_pool = []
    ip_pool.append(GetOuterIP('chinaz'))
    ip_pool.append(GetOuterIP('ipplus360'))
    ip_pool.append(GetOuterIP('ip138'))
    ip_pool = list(set(ip_pool))

    new_ip_pool = []
    num_get_fail = 0
    for ip in ip_pool:
        ip = ip.strip()
        append_to_new = True
        if ("改版") in ip:
            ip_pool.remove(ip)
            append_to_new = False
            num_get_fail += 1
            continue
        elif ip.find("改版") != -1:
            ip_pool.remove(ip)
            append_to_new = False
            num_get_fail += 1
            continue
        elif "Bad" in ip:
            ip_pool.remove(ip)
            append_to_new = False
            continue
        elif " " in ip:
            ip_pool.remove(ip)
            append_to_new = False
            continue
        elif "." not in ip:
            ip_pool.remove(ip)
            append_to_new = False
            continue
        else:
            items = re.findall(r"\d+.\d+.\d+.\d+", ip)
            for item in items:
                inode = item.split(".")
                for node in inode:
                    if len(node) > 3:
                        ip_pool.remove(ip)
                        append_to_new = False
                        continue
                    if int(node) > 255:
                        ip_pool.remove(ip)
                        append_to_new = False
                        continue
            if append_to_new == True:
                new_ip_pool.append(ip)
            pass
    if num_get_fail > 2:
        loguru.logger.error("获取IP地址失败")
        console_print("获取IP地址失败")
        chk_inet_access()
        return
    history_ip = list(set(history_ip))

    ip_pool = list(set(new_ip_pool))

    new_ip_pool = []
    for ip in ip_pool:
        append_to_new = True
        if ip in history_ip:
            append_to_new = False
            ip_pool.remove(ip)
        else:
            new_ip_pool.append(ip)

    ip_pool = list(set(new_ip_pool))
    if ip_pool != []:
        for ip in ip_pool:
            history_ip.append(ip)
            with open("history_ip.log", "a", encoding="utf-8") as f:
                f.write(ip+"\n")

    ip_pool = str(ip_pool)
    if ip_pool == last_ip:
        loguru.logger.info("IP地址未变化，不发送邮件")
        console_print("IP地址未变化，不发送邮件")
        return
    elif ip_pool == "[]":
        loguru.logger.info("IP地址为历史IP，不发送邮件")
        console_print("IP地址为历史IP，不发送邮件")
        return
    else:
        last_ip = ip_pool
    console_print("NewIP:" + ip_pool)

    contents = "IP地址变化为："+ip_pool+"<br>请注意查看,历史IP地址为："+str(history_ip)
    if chkIPchangeEmail == 1:
        send_email(mail_title, contents, email_receivers, smtp_host,
                   smtp_port, mail_user, mail_pass, sender_email, smtptype)


def get_time():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


InetAccessMsg = ""


def chk_inet_access():
    global InetAccessLog, InetAccessMsg
    InetAccess = True
    timestr = get_time()
    try:
        url = r'https://www.baidu.com'
        data = requests.get(url, headers=headers,
                            verify=False, timeout=10).content.decode('utf-8')
        # print(data)
        loguru.logger.info("网络访问正常"+timestr)
        console_print("网络访问正常"+timestr)
        InetAccessLog.append("网络访问正常"+timestr)
        InetAccess = True
    except:
        loguru.logger.error("网络访问异常"+timestr)
        console_print("网络访问异常"+timestr)
        InetAccessLog.append("网络访问异常"+timestr)
        InetAccess = False
    if len(InetAccessLog) > 60:
        InetAccessLog = InetAccessLog[-60:]
    with open("InetAccess.log", "w", encoding="utf-8") as f:
        for log in InetAccessLog:
            f.write(log+"\n")
    if InetAccess == False:
        InetAccessMsg = str(InetAccessLog)
        return False
    else:
        if InetAccessMsg != "":
            if chkInetAccessEmail == 1:
                send_email("网络访问异常", InetAccessMsg, email_receivers, smtp_host,
                           smtp_port, mail_user, mail_pass, sender_email, smtptype)
            InetAccessMsg = ""
        return True


def prepare_conf_file(configpath):  # 准备配置文件
    if os.path.isfile(configpath) == True:
        pass
    else:
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
        config.set("Email", "chkIPchange", r"1")
        config.set("Email", "chkIPchangeEmail", r"1")
        config.set("Email", "chkIPchangeInterval", r"60")
        config.set("Email", "chkInetAccess", r"1")
        config.set("Email", "chkInetAccessEmail", r"1")
        config.set("Email", "chkInetAccessInterval", r"3600")
        # write to file
        config.write(open(configpath, "w"))
        pass
    pass


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
    with open(config_path, "rb") as f:
        result = chardet.detect(f.read())
        encoding = result["encoding"]
    config.read(config_path, encoding=encoding)
    conf_item_settings = []
    for conf_item in conf_list:
        try:
            conf_item_setting = config[config_section][conf_item]

            # 获取 列表类型的配置项
            if conf_item == "piserver" or conf_item == "email_receivers":
                item_nodes = conf_item_setting.split(",")
                conf_item_setting = []
                for item_node in item_nodes:
                    conf_item_setting.append(item_node)
                # print(conf_item_setting)
        except Exception as e:
            conf_item_setting = conf_default[conf_item]

        console_print(str(conf_item) + ":" + str(conf_item_setting))
        conf_item_settings.append(conf_item_setting)
        pass
    if len(conf_list) > 1:
        return tuple(conf_item_settings)
    else:
        return conf_item_settings[0]


def on_quit():
    global icon
    icon.stop()
    os._exit(0)


def sw_console():
    global console_show
    if console_show == 0:
        mainwin.deiconify()
        console_show = 1
    else:
        mainwin.withdraw()
        console_show = 0
    pass


def get_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


def textpad_insert(text, f):
    f = str(f)
    if text.get("1.0", "end") == "\n":
        text.insert(tk.END, f)
    else:
        text.insert(tk.END, f+"\n")
    pass


def console_print(text):
    global textpad
    mainwin.after(500, textpad_insert, textpad, text)
    pass


def set_email():
    global email_receivers, smtp_host, smtp_port, mail_user, mail_pass, sender_email, smtptype, mail_title
    import tkinter as tk
    from tkinter import ttk
    from tkinter import messagebox

    def save_email():
        email_receivers = email_receivers_entry.get()
        smtp_host = smtp_host_entry.get()
        smtp_port = smtp_port_entry.get()
        mail_user = mail_user_entry.get()
        mail_pass = mail_pass_entry.get()
        sender_email = sender_email_entry.get()
        smtptype = smtptype_entry.get()
        mail_title = mail_title_entry.get()
        config.set("Email", "smtp_host", smtp_host)
        config.set("Email", "smtp_port", smtp_port)
        config.set("Email", "mail_user", mail_user)
        config.set("Email", "mail_pass", mail_pass)
        config.set("Email", "sender_email", sender_email)
        config.set("Email", "email_receivers", email_receivers)
        config.set("Email", "smtptype", smtptype)
        config.set("Email", "title", mail_title)
        config.write(open(configpath, "w"))
        messagebox.showinfo("提示", "保存成功")
        setwin.destroy()
        pass

    def cancel_email():
        setwin.destroy()
        pass

    smtp_host = str(smtp_host)
    smtp_port = str(smtp_port)
    mail_user = str(mail_user)
    mail_pass = str(mail_pass)
    sender_email = str(sender_email)
    smtptype = str(smtptype)
    mail_title = str(mail_title)
    setwin = tk.Toplevel()
    setwin.title("设置电子邮件")
    setwin.geometry("400x300")
    setwin.resizable(0, 0)
    # setwin.iconbitmap("ip.ico")

    email_receivers_label = ttk.Label(setwin, text="收件人：")
    email_receivers_label.place(x=10, y=10, width=80, height=20)
    email_receivers_entry = ttk.Entry(setwin)
    email_receivers_entry.place(x=100, y=10, width=280, height=20)
    tomail = ""
    for mail in email_receivers:
        if tomail == "":
            tomail = mail
        else:
            tomail = tomail+","+mail

    email_receivers_entry.insert(0, email_receivers)
    smtp_host_label = ttk.Label(setwin, text="SMTP服务器：")
    smtp_host_label.place(x=10, y=40, width=80, height=20)
    smtp_host_entry = ttk.Entry(setwin)
    smtp_host_entry.place(x=100, y=40, width=280, height=20)
    smtp_host_entry.insert(0, smtp_host)
    smtp_port_label = ttk.Label(setwin, text="SMTP端口：")
    smtp_port_label.place(x=10, y=70, width=80, height=20)
    smtp_port_entry = ttk.Entry(setwin)
    smtp_port_entry.place(x=100, y=70, width=280, height=20)
    smtp_port_entry.insert(0, smtp_port)
    mail_user_label = ttk.Label(setwin, text="邮箱账号：")
    mail_user_label.place(x=10, y=100, width=80, height=20)
    mail_user_entry = ttk.Entry(setwin)
    mail_user_entry.place(x=100, y=100, width=280, height=20)
    mail_user_entry.insert(0, mail_user)
    mail_pass_label = ttk.Label(setwin, text="邮箱密码：")
    mail_pass_label.place(x=10, y=130, width=80, height=20)
    mail_pass_entry = ttk.Entry(setwin)
    mail_pass_entry.place(x=100, y=130, width=280, height=20)
    mail_pass_entry.insert(0, mail_pass)
    sender_email_label = ttk.Label(setwin, text="发件人：")
    sender_email_label.place(x=10, y=160, width=80, height=20)
    sender_email_entry = ttk.Entry(setwin)
    sender_email_entry.place(x=100, y=160, width=280, height=20)
    sender_email_entry.insert(0, sender_email)
    smtptype_label = ttk.Label(setwin, text="加密方式：")
    smtptype_label.place(x=10, y=190, width=80, height=20)
    smtptype_entry = ttk.Entry(setwin)
    smtptype_entry.place(x=100, y=190, width=280, height=20)
    smtptype_entry.insert(0, smtptype)
    mail_title_label = ttk.Label(setwin, text="邮件标题：")
    mail_title_label.place(x=10, y=220, width=80, height=20)
    mail_title_entry = ttk.Entry(setwin)
    mail_title_entry.place(x=100, y=220, width=280, height=20)
    save_btn = ttk.Button(setwin, text="保存", command=save_email)
    save_btn.place(x=100, y=250, width=80, height=30)
    cancel_btn = ttk.Button(setwin, text="取消", command=cancel_email)
    cancel_btn.place(x=200, y=250, width=80, height=30)


def new_thread(func):

    @wraps(func)
    def inner(*args, **kwargs):
        # print(f'函数的名字：{func.__name__}')
        # print(f'函数的位置参数：{args}')
        thread = threading.Thread(target=func, args=args, kwargs=kwargs)
        thread.start()

    return inner


@new_thread
def systray():
    global icon
    menu_options = pystray.Menu(
        pystray.MenuItem("设置电子邮件", set_email),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("控制台", sw_console),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("退出", on_quit)
    )
    icon = pystray.Icon(name="外网IP监视器", icon=Image.open(
        get_resource_path("./ip.png")), menu=menu_options, on_quit=on_quit)
    icon.run()


@new_thread
def app():
    while True:
        schedule.run_pending()
        time.sleep(10)


if __name__ == "__main__":
    icon = ''
    systray()
    import tkinter as tk
    mainwin = tk.Tk()
    mainwin.title("控制台")
    mainwin.geometry("600x600")
    textpad = tk.Text(mainwin, undo=False)
    textpad.pack(expand=True, fill='both')
    textpad.insert(tk.END, "开启控制台\n")
    config = configparser.ConfigParser()  # 类实例化

    # 定义文件路径
    configpath = r".\setup.ini"
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

    last_ip = ''
    history_ip = []
    InetAccessLog = []
    if os.path.exists("history_ip.log") == False:
        with open("history_ip.log", "w", encoding="utf-8") as f:
            f.write("")
    with open("history_ip.log", "r", encoding="utf-8") as f:
        for line in f:
            if line.strip() != "":
                history_ip.append(line.strip())
    history_ip = list(set(history_ip))
    if history_ip != []:
        with open("history_ip.log", "w", encoding="utf-8") as f:
            for ip in history_ip:
                f.write(ip+"\n")

    sheduler = loguru.logger.add(
        "daemon_ip_chg.log", rotation="1 day", retention="7 days", level="INFO", encoding="utf-8")
    if chk_inet_access() == True:
        chk_ipchg()
    if chkIPchange == 1:
        schedule.every(chkIPchangeInterval).seconds.do(chk_ipchg)  # 每60秒执行一次
    if chkInetAccess == 1:
        schedule.every(chkInetAccessInterval).seconds.do(
            chk_inet_access)  # 每1小时执行一次
    app()

    console_show = 1
    mainwin.protocol("WM_DELETE_WINDOW", sw_console)
    mainwin.withdraw()
    console_show = 0

    console_print(history_ip)

    mainwin.mainloop()
