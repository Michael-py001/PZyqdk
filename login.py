import re
import urllib.request
import http.cookiejar
from bs4 import BeautifulSoup
from utils import log_write, baidu_ocr
from utils.student_data import get_data, get_data_bat
from utils.chaojiying import Chaojiying_Client
from utils.push_news import push_news, push_my_news, money_news, push_no_name_news, push_is_dk_news
import random
import time
import logging
import json

file_handler = logging.FileHandler("login_data.log", mode="a", encoding="utf-8")
logging.basicConfig(format='[%(asctime)s] %(message)s', datefmt='%I:%M:%S', level=logging.INFO, handlers={file_handler})
logger = logging.getLogger(__name__)


def login(id, pwd, key):
    '''
    
    :param id: 学号
    :param pwd: 密码
    :return: 
    '''
    random_str = ''
    for i in range(4):
        num = random.randint(0, 9)
        random_str += str(num)
    # print(random_str)
    # 姓名
    name = ''
    # 登录页面
    login_url = 'http://rb.peizheng.edu.cn/login.php'
    # 验证码
    code_url = 'http://rb.peizheng.edu.cn/captcha.php?{}'.format(random_str)
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;0.9,image/webp,image/apng,*/*;q=0.8,application/signed- xchange;v=b3;q =0.9',
        'Host': 'rb.peizheng.edu.cn',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'http://rb.peizheng.edu.cn',
        'Referer': 'http://rb.peizheng.edu.cn/login.php',
        'User-Agent': 'Mozilla/5.0 (Linux; U; Android 4.3; en-us; SM-N900T Build/JSS15J) AppleWebKit/534.30 (KHTML, like Gecko) Version/4 .0 Mobile Safari/534.30'

    }
    # 构造获取登录页面的html请求，
    req_html = urllib.request.Request(login_url, headers=headers)
    import time
    time.sleep(1)
    # 构造获取图片内容请求
    req_code = urllib.request.Request(code_url, headers=headers)
    # 构造cookie
    cookie = http.cookiejar.CookieJar()
    # 由cookie构造opener
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie))
    try:
        # 发送登录请求，此后这个opener就携带了cookie，以证明自己登录过
        resp_html = opener.open(req_html)  # 打开登录页面，获取html
        print("打开登录页面状态码", resp_html.getcode())
        if (resp_html.getcode() == 200):
            print("打开首页正常")
            logger.info("打开首页正常")
        elif (resp_html.getcode() == 403):
            print("你被ban了")
            return
        elif (resp_html.getcode() == 504):
            print("请求超时")
            return
        else:
            print("打不开首页！错误！")
            return
        resp_code = opener.open(req_code)  # 打开验证码url，获取二进制内容
        # print(resp_html)
        # html页面解码
        html = resp_html.read().decode('utf-8')
        # print(html)
        # 正则解析获取token
        token = re.findall('token=(.*)">', html)
        token_str = str(token)[2:-2]  # token
        # 获取图片二进制内容
        img_data = resp_code.read()
    except Exception as e:
        print(e)
        print("获取图片验证码失败")
        return {"msg": '获取图片验证码失败', "code": 399}
    try:
        # 保存图片到本地
        with open('yzm.jpg', mode='wb') as f:
            f.write(img_data)
        # valc = input("输入验证码")
        try:
            # 调用打码平台接口
            chaojiying = Chaojiying_Client('13360267368', '19980203qq@@', '907854')
            im = open('yzm.jpg', 'rb').read()
            code_result = chaojiying.PostPic(im, 1902)
            code_result_str = code_result["pic_str"]
            print(code_result_str, "自动打码成功！")
            logger.info("自动打码成功！")
        except Exception as e:
            print("自动打码失败")
            logger.info("自动打码失败")
            return {"msg": '自动打码失败', "code": 400}
    except Exception as e:
        logger.info("读取验证码图片错误")
        print("读取验证码图片错误")
    try:
        # print(code_result)
        # 准备好token&验证码后，开始post登录
        login_post_url = 'http://rb.peizheng.edu.cn/login_do.php?token=' + token_str
        # print(login_post_url)
        data = {
            'username': str(id),
            'pwd': str(pwd),
            'validate': code_result_str  # code_result
        }
        post_data = urllib.parse.urlencode(data).encode('utf-8')

        req_post = urllib.request.Request(login_post_url, headers=headers, data=post_data)
        resp_post = opener.open(req_post)  # 请求登录
        resp_post_content = resp_post.read().decode("utf-8")
        # print(resp_post_content)
        # 获取登录提示（密码错误。。。）
        soup = BeautifulSoup(resp_post_content, 'lxml')
        tips_div = soup.select_one("div[id='content']")
        if (tips_div is not None):
            tips = tips_div.get_text().strip()
            print("登录提示：", tips)
            if (resp_post.getcode() == 200 and tips == "用户名与密码不正确"):
                print("用户名与密码不正确")
                logger.info("用户名与密码不正确")
                return {"msg": "用户名与密码不正确", "code": 405}
            elif (resp_post.getcode() == 200 and tips == "验证码不正确"):
                print("验证码不正确")
                logger.info("验证码不正确")
                error_result = chaojiying.ReportError(code_result["pic_id"])
                print("验证码不正确上报成功", error_result)
                logger.info("验证码不正确上报成功")
                return {"code": 410}
            else:
                print("未知错误！")
                return
        elif (tips_div is None):
            try:
                # 登录成功则获取姓名
                soup = BeautifulSoup(resp_post_content, 'lxml')
                student_name = soup.select_one("h3[style='padding-left:10px;']")
                name = student_name.get_text()[5:].strip()
                if (name is not None):
                    print("{name}--{id}--{pwd}--登录首页成功".format(name=name, id=id, pwd=pwd))
                    logger.info(f"{name}--{id}--{pwd}--登录首页成功".format(name=name, id=id, pwd=pwd))
                    try:
                        # 开始进入上报数据页面
                        # 登录后才能访问的上报页面
                        put_data_url = 'http://rb.peizheng.edu.cn/xs/rb.php'
                        # 构造访问请求
                        req = urllib.request.Request(put_data_url, headers=headers)
                        resp = opener.open(req)
                        status_code = resp.getcode()
                        print('上报数据页面状态码', status_code)
                        # print(status_code)
                        resp_content = resp.read().decode('utf-8')
                        if ("不在统计时间范围" in resp_content):
                            print("不在统计时间范围")
                            logger.info("不在统计时间范围")
                            return
                        else:
                            # 正则解析获取上报token
                            token = re.findall('token=(.*)" id="myForm', resp_content)
                            # print(len(token))
                            # print("token:",token)
                            if (len(token) == 1):
                                token_post = token[0]  # token
                                if (token_post is not None or token_post != ""):
                                    try:
                                        # 提交的地址
                                        data_post_url = 'http://rb.peizheng.edu.cn/xs/rb_do.php?token=' + token_post
                                        # 提交的 post数据
                                        data = {
                                            'rb': 'YES',
                                            'level': '1',
                                            'content': ''
                                        }
                                        post_data = urllib.parse.urlencode(data).encode('utf-8')
                                        # 构造post提交数据请求
                                        req = urllib.request.Request(data_post_url, headers=headers, data=post_data)
                                        resp = opener.open(req)
                                        resp_content = resp.read().decode("utf-8")
                                        status_code = resp.getcode()
                                        print("提交打卡状态码", status_code)
                                        if (status_code == 200):
                                            # print(resp_content)
                                            if resp_content.find("您的信息已经成功添加") != -1:
                                                new = "成功打卡"
                                                # 调用外部函数，写入成功日志
                                                log_write.write_log(id, name, new)
                                                logger.info(f"{id}--{name}-成功打卡".format(id=id, name=name))
                                                if (key != ""):
                                                    # 推送消息
                                                    time = log_write.is_in_time()
                                                    push_news(name, time, key)
                                                return
                                            elif resp_content.find("您已经登记过了，请不要重复上报") != -1:
                                                logger.info("您已经登记过了，请不要重复上报")
                                                print("您已经登记过了，请不要重复上报")
                                                return
                                            else:
                                                print("POST成功但是打卡失败,status_code:200")
                                                logger.info("POST成功但是打卡失败,status_code:200")
                                                return {"msg": "POST成功但是打卡失败", "code": 416}
                                        else:
                                            print("提交打卡POST未知错误！")
                                            logger.info("提交打卡POST未知错误！")
                                            return
                                    except Exception as e:
                                        print('TOKEN获取失败，提交POST请求失败')
                                        logger.info('TOKEN获取失败，提交POST请求失败')
                                        return {"msg": 'TOKEN获取失败，提交POST请求失败', "code": 404}
                            elif (len(token) == 0):
                                new = "您已经打卡过"
                                logger.info("您这个时间段已经提交过，请下个时间段再来")
                                print("您这个时间段已经提交过，请下个时间段再来")
                                log_write.write_log(id, name, new)
                                if (key != ""):
                                    # 推送已经打卡消息给用户
                                    push_is_dk_news(name, key)
                                return
                            else:
                                logger.info("获取token，未知错误")
                                print("获取token，未知错误")
                                return
                        # except Exception as e:
                        #     print('获取token失败/您或许已经提交过')
                        #     return {"msg": '获取token失败/您或许已经提交过', "code": 403}

                    except Exception as e:
                        print("进入登记页面失败")
                        logger.info("进入登记页面失败")
                        return {"msg": '进入登记页面失败', "code": 402}

                else:
                    print("获取不到姓名，错误414-学号：", id)
                    logger.info("获取不到姓名，错误414")
                    if (key != ""):
                        # 推送获取不到姓名消息给用户
                        push_no_name_news(id)

                    return {"code": 414}
            except Exception as e:
                print(e)
                print("获取不到姓名,错误415学号：", id)
                logger.info("获取不到姓名，错误415")
                if (key != ""):
                    # 推送获取不到姓名消息给用户
                    push_no_name_news(id)
                return {"code": 415}

    except Exception as e:
        print(e)
        print("登录首页失败/验证码错误")
        logger.info("登录首页失败/验证码错误")
        return {"msg": '登录失败，请检查账号密码', "code": 401}


def login_2(id, pwd, key):
    '''

    :param id: 学号
    :param pwd: 密码
    :return:
    '''
    try_num = 0
    import time
    start_time = time.time()
    for i in range(300):
        try_num += 1
        random_str = ''
        for i in range(4):
            num = random.randint(0, 9)
            random_str += str(num)
        # print(random_str)
        # 姓名
        name = ''
        # 登录页面
        login_url = 'http://rb.peizheng.edu.cn/login.php'
        # 验证码
        code_url = 'http://rb.peizheng.edu.cn/captcha.php?{}'.format(random_str)
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;0.9,image/webp,image/apng,*/*;q=0.8,application/signed- xchange;v=b3;q =0.9',
            'Host': 'rb.peizheng.edu.cn',
            'Upgrade-Insecure-Requests': '1',
            'Origin': 'http://rb.peizheng.edu.cn',
            'Referer': 'http://rb.peizheng.edu.cn/login.php',
            'User-Agent': 'Mozilla/5.0 (Linux; U; Android 4.3; en-us; SM-N900T Build/JSS15J) AppleWebKit/534.30 (KHTML, like Gecko) Version/4 .0 Mobile Safari/534.30'

        }
        # 构造获取登录页面的html请求，
        req_html = urllib.request.Request(login_url, headers=headers)
        import time
        time.sleep(1)
        # 构造获取图片内容请求
        req_code = urllib.request.Request(code_url, headers=headers)
        # 构造cookie
        cookie = http.cookiejar.CookieJar()
        # 由cookie构造opener
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie))
        # 发送登录请求，此后这个opener就携带了cookie，以证明自己登录过
        resp_html = opener.open(req_html)  # 打开登录页面，获取html
        if (resp_html.getcode() == 200):
            pass
        elif (resp_html.getcode() == 403):
            print("你被ban了")
            break
        elif (resp_html.getcode() == 504):
            print("请求超时")
            break
        else:
            print("打不开首页！错误！")
            break
        resp_code = opener.open(req_code)  # 打开验证码url，获取二进制内容
        # print(resp_html)
        # html页面解码
        html = resp_html.read().decode('utf-8')
        # print(html)
        # 正则解析获取token
        token = re.findall('token=(.*)">', html)
        token_str = str(token)[2:-2]  # token
        # 获取图片二进制内容
        img_data = resp_code.read()

        # 保存图片到本地
        with open('yzm.jpg', mode='wb') as f:
            f.write(img_data)
        # valc = input("输入验证码")
        # 调用打码平台接口
        im = open('yzm.jpg', 'rb').read()
        code_result_str = baidu_ocr.img_ocr(im)
        # print(code_result_str)
        if (len(code_result_str) == 4):
            print(code_result_str, "自动打码成功！")
            logger.info("自动打码成功！")
            # print(code_result)
            # 准备好token&验证码后，开始post登录
            login_post_url = 'http://rb.peizheng.edu.cn/login_do.php?token=' + token_str
            # print(login_post_url)
            data = {
                'username': str(id),
                'pwd': str(pwd),
                'validate': code_result_str  # code_result
            }
            post_data = urllib.parse.urlencode(data).encode('utf-8')

            req_post = urllib.request.Request(login_post_url, headers=headers, data=post_data)
            resp_post = opener.open(req_post)  # 请求登录
            resp_post_content = resp_post.read().decode("utf-8")
            # print(resp_post_content)
            # 获取登录提示（密码错误。。。）
            soup = BeautifulSoup(resp_post_content,"html.parser")
            tips_div = soup.select_one("div[id='content']")
            if (tips_div is not None):
                tips = tips_div.get_text().strip()
                print("登录提示：", tips)
                if (resp_post.getcode() == 200 and tips == "用户名与密码不正确"):
                    print("用户名与密码不正确")
                    logger.info("用户名与密码不正确")
                    break
                elif (resp_post.getcode() == 200 and tips == "验证码不正确"):
                    print("验证码不正确")
                    logger.info("验证码不正确")
                    continue
                else:
                    print("未知错误！")
                    break
            elif (tips_div is None):
                # 登录成功则获取姓名
                soup = BeautifulSoup(resp_post_content, 'html.parser')
                student_name = soup.select_one("h3[style='padding-left:10px;']")
                name = student_name.get_text()[5:].strip()
                if (name is not None):
                    print("{name}--{id}--{pwd}--登录首页成功".format(name=name, id=id, pwd=pwd))
                    logger.info(f"{name}--{id}--{pwd}--登录首页成功".format(name=name, id=id, pwd=pwd))
                    # 开始进入上报数据页面
                    # 登录后才能访问的上报页面
                    put_data_url = 'http://rb.peizheng.edu.cn/xs/rb.php'
                    # 构造访问请求
                    req = urllib.request.Request(put_data_url, headers=headers)
                    resp = opener.open(req)
                    status_code = resp.getcode()
                    print('上报数据页面状态码', status_code)
                    # print(status_code)
                    resp_content = resp.read().decode('utf-8')
                    if ("不在统计时间范围" in resp_content):
                        print("不在统计时间范围")
                        logger.info("不在统计时间范围")
                        return
                    else:
                        # 正则解析获取上报token
                        token = re.findall('token=(.*)" id="myForm', resp_content)
                        # print(len(token))
                        # print("token:",token)
                        if (len(token) == 1):
                            token_post = token[0]  # token
                            if (token_post is not None or token_post != ""):
                                # 提交的地址
                                data_post_url = 'http://rb.peizheng.edu.cn/xs/rb_do.php?token=' + token_post
                                # 提交的 post数据
                                data = {
                                    'rb': 'YES',
                                    'level': '1',
                                    'content': ''
                                }
                                post_data = urllib.parse.urlencode(data).encode('utf-8')
                                # 构造post提交数据请求
                                req = urllib.request.Request(data_post_url, headers=headers, data=post_data)
                                resp = opener.open(req)
                                resp_content = resp.read().decode("utf-8")
                                status_code = resp.getcode()
                                print("提交打卡状态码", status_code)
                                if (status_code == 200):
                                    # print(resp_content)
                                    if resp_content.find("您的信息已经成功添加") != -1:
                                        new = "成功打卡"
                                        # 调用外部函数，写入成功日志
                                        log_write.write_log(id, name, new)
                                        logger.info(f"{id}--{name}-成功打卡".format(id=id, name=name))
                                        print("尝试登陆次数：", try_num)
                                        end_time = time.time()
                                        total_time = int(end_time - start_time)
                                        print("单个账号用时：%d秒" % total_time)
                                        if (key != ""):
                                            # 推送消息
                                            time = log_write.is_in_time()
                                            push_news(name, time, key, total_time, try_num)
                                        return {"code": 200}
                                    else:
                                        print("POST成功但是打卡失败,status_code:200")
                                        logger.info("POST成功但是打卡失败,status_code:200")
                                        break
                                else:
                                    print("提交打卡POST未知错误！")
                                    logger.info("提交打卡POST未知错误！")
                                    break

                        elif (len(token) == 0):
                            new = "您已经打卡过"
                            logger.info("您这个时间段已经提交过，请下个时间段再来")
                            print("您这个时间段已经提交过，请下个时间段再来")
                            print("尝试登陆次数：", try_num)
                            end_time = time.time()
                            total_time = int(end_time - start_time)
                            print("单个账号用时：%d秒" % total_time)
                            log_write.write_log(id, name, new)
                            if (key != ""):
                                # 推送已经打卡消息给用户
                                push_is_dk_news(name, key)
                            return {"code": 201}
                        else:
                            logger.info("获取token，未知错误")
                            print("获取token，未知错误")
                            break
                else:
                    print("获取不到姓名，错误414-学号：", id)
                    logger.info("获取不到姓名，错误414")
                    if (key != ""):
                        # 推送获取不到姓名消息给用户
                        push_no_name_news(id)

                    break
        else:
            # print("验证码：%s"%code_result_str)
            continue
    print("尝试次数%d" % try_num)
    return


def all_login():
    # 调用打码平台接口
    chaojiying = Chaojiying_Client('13360267368', '19980203qq@@', '907854')
    # 成功数
    ssuccess_num = 0
    # 失败数
    err_num = 0
    log_write.write_strat("本轮开始")
    # with open(r'G:\Pythonpeixun\PZyiqingdaka\student_data.json','r') as f:
    #     data_dict = json.load(f)
    student_data = get_data()
    # print(student_data)
    # 记录余额
    money_end = 0
    for item in student_data:
        money = chaojiying.CheckMoney()
        money_end = money
        if (money < 10):
            # 余额不足提示
            money_news(money)
            break
        elif (money >= 10):
            id = str(item['id'])
            pwd = str(item['pwd'])
            key = str(item['key'])

            # 开启登录提交数据
            result_code = login(id, pwd, key)

            # 判断打码登录是否失败，超出次数跳出
            print(result_code)
            if (result_code != None):

                # 验证码错误情况
                if ("code" in result_code and (
                        result_code["code"] == 410 or result_code["code"] == 399 or result_code["code"] == 400 or
                        result_code["code"] == 414 or result_code["code"] == 415 or result_code["code"] == 416)):
                    print(result_code["code"])
                    if (result_code["code"] == 414 or result_code["code"] == 415):
                        print("推送获取不到姓名消息给用户")
                        logger.info("推送获取不到姓名消息给用户")
                        push_no_name_news(id, key)
                    print("重新打码")
                    logger.info("重新打码")
                    # 再次执行登录
                    login(id, pwd, key)
                    ssuccess_num += 1
                    # 记录成功次数
                else:
                    print("result_code", result_code)
                    logger.info("result_code")
                    err_num += 1
            elif (result_code == None):
                ssuccess_num += 1
                print("-----------------下一位-------------")
                logger.info("-----------------下一位-------------")
    print("本轮全部打卡完毕")
    logger.info("本轮全部打卡完毕")
    log_write.write_strat("本轮结束")
    # 微信通知完成任务
    push_my_news(ssuccess_num, err_num)
    time.sleep(1)
    # 推送余额
    money_news(money_end)
    return {"msg": "全部打卡完毕"}


def all_login_2():
    start_time = time.time()
    # 成功数
    ssuccess_num = 0
    # 失败数
    err_num = 0
    log_write.write_strat("本轮开始")
    # with open(r'G:\Pythonpeixun\PZyiqingdaka\student_data.json','r') as f:
    #     data_dict = json.load(f)
    with open(r'G:\Pythonpeixun\PZyiqingdaka\student_data.json', 'r') as f:
        data_dict = json.load(f)
    student_data = data_dict
    # print(student_data)

    for item in student_data:

        id = str(item['id'])
        pwd = str(item['pwd'])
        key = str(item['key'])

        # 开启登录提交数据
        result_code = login_2(id, pwd, key)
        print("result_code", result_code)
        # 判断打码登录是否失败，超出次数跳出
        if (result_code != None):
            # 验证码错误情况
            if (result_code["code"] == 200 or result_code["code"] == 201):
                print("打卡成功--下一位")
                # time.sleep(1)
                ssuccess_num += 1
                continue
            else:
                print("小错误出现！")
                err_num += 1
                continue
        elif (result_code == None or result_code == ""):
            print("------下一位------")
            ssuccess_num += 1
            # time.sleep(1)
            continue

    print("本轮全部打卡完毕")
    logger.info("本轮全部打卡完毕")
    log_write.write_strat("本轮结束")

    end_time = time.time()
    total_time = int(end_time - start_time)
    print("全程用时：%d秒" % total_time)
    # 微信通知完成任务
    push_my_news(ssuccess_num, err_num, total_time)
    return {"msg": "全部打卡完毕"}


# all_login()
# key = "SCU95639T467b8def0b8e5b724ae332d6e6f74d0c5ea5ddcfb0d63" #我自己的key
# key="SCU112924T4e77afd5e6b3aa89bf06fc596ec76b2c5f58912831799"


if __name__ == '__main__':
    # login_2(201751709114, 123456, "SCU95639T467b8def0b8e5b724ae332d6e6f74d0c5ea5ddcfb0d63")
    # all_login()  # pycharm 里运行的
    all_login_2()  # 百度识别版本
    # all_login_bat()  # bat里运行的
