import os, sys, time, re, smtplib, func_timeout, loguru, requests, pyquery, json, schedule
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
requests.packages.urllib3.disable_warnings()
# python -m venv ./.venv
# .\.venv\Scripts\Activate.ps1

# pyinstaller -F daemon_ip_chg_noemail.py

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
    if method=="chinaz":
        try:
            url = r'https://ip.chinaz.com/'
            data=requests.get(url,headers=headers, verify=False).content.decode('utf-8')
            #print(data)
            d = pyquery.PyQuery(data) 
            ip = str(d('#ip').text() )
            #print(ip)
        except:
            ip="无法获取，可能是网站改版，请手动访问 https://ip.chinaz.com"
        loguru.logger.info("IP地址："+ip+"")
        return ip
    elif method=="ipplus360":
        try:
            url = r'https://www.ipplus360.com/getIP'
            data=requests.get(url, verify=False).content.decode('utf-8')
            # print(data)
            # {"success":true,"code":200,"msg":"获取用户端IP成功","data":""}
            d = json.loads(data)
            ip=d['data']
            #print(ip)
        except:
            ip="无法获取，可能是网站改版，请手动访问 https://www.ipplus360.com"
        loguru.logger.info("IP地址："+ip+"")
        return ip
    elif method=="ip138":
        try:
            url = r'https://2024.ip138.com/'
            data=requests.get(url,headers=headers, verify=False).content.decode('utf-8')
            #print(data)
            d = pyquery.PyQuery(data)
            ip = str(d('title').text())
            ip=ip.replace("您的IP地址是：","")
            #print(ip)
        except:
            ip="无法获取，可能是网站改版，请手动访问 https://2024.ip138.com/"
        loguru.logger.info("IP地址："+ip+"")
        return ip
    else:
        loguru.logger.error("未知的获取IP地址方法")
        ip="未知的获取IP地址方法"
        return ip
def send_email_ipchg():
    global last_ip
    # 设置登录及服务器信息
    ip_pool=[]
    ip_pool.append(GetOuterIP('chinaz'))
    ip_pool.append(GetOuterIP('ipplus360'))
    ip_pool.append(GetOuterIP('ip138'))
    for ip in ip_pool:
        if "无法获取" in ip:
            ip_pool.remove(ip)
            continue
        if "Bad" in ip:
            ip_pool.remove(ip)
            continue
        if " " in ip:
            ip_pool.remove(ip)
            continue
        if "." not in ip:
            ip_pool.remove(ip)
            continue
        else:
            items = re.findall(r"\d+.\d+.\d+.\d+", ip)
            for item in items:
                if int(item) > 255:
                    ip_pool.remove(ip)
                    continue
            pass
    ip_pool = list(set(ip_pool))
    for ip in ip_pool:
        if ip in history_ip:
            ip_pool.remove(ip)
    for ip in ip_pool:
        history_ip.append(ip)
    ip_pool = str(ip_pool)
    if ip_pool==last_ip:
        loguru.logger.info("IP地址未变化，不发送邮件")
        return
    elif ip_pool=="[]":
        loguru.logger.info("IP地址为历史IP，不发送邮件")
        return
    else:
        last_ip=ip_pool
    print("IP地址变化为："+ip_pool+"请注意查看,历史IP地址为："+str(history_ip))

if __name__ == "__main__":
    last_ip=''
    history_ip=[]
    
    sheduler = loguru.logger.add("daemon_ip_chg.log", rotation="1 day", retention="7 days", level="INFO")
    send_email_ipchg()
    schedule.every(60).seconds.do(send_email_ipchg)  # 每10秒执行一次
    
    while True:
        schedule.run_pending()
        time.sleep(10)