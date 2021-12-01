from model.model import * 
print("""
                                                  欢迎使用！！！
                                   由于不可抗拒的原因，本人的编写代码的技术能力有限，所以
                                如果使用过程中有什么不足之处请联系作者：3305019948@qq.com
                                您的反馈和指正就是我们发展的最大动力！！！
版本：AWD_hacking_v3.0
时间：2021/10/11
作者：破壳雏鸟
                                                   功能选区    
                                                   
                                           1----->ssh弱密码测试
                                           2----->get/post主办方后门批量测试
                                           3----->get微型木马连接器
                                           4----->post微型木马连接器
                                           5----->mysql弱密码测试
                                           6----->一句话木马生成器
                                           7----->检测文件
                                           8----->攻击选手电脑(win10-1909)
""")
ssh_hacking = SshHack()
web_hacking = WebHack()
mysql_hacking = MysqlCon()
trojan = Tro_horse("./data/trojan/")
hackcve = PocAttack()
fileche = FileCheck()
try:
    opt = input("请输入功能对应的数字调用对应功能：")
    if opt == '1':
        print("请在运行前确认已填写好./config/ssh.txt配置文件")
        input("按回车键继续...")
        ssh_hacking.sshBatch("./config/ssh.txt")
    elif opt == '2':
        input("请在运行之前确认已填写好./config/web.txt配置文件\n按回车键继续...")
        web_hacking.reqBatch("./config/web.txt")
    elif opt == '3':
        web_hacking.getCmd()
    elif opt == '4':
        web_hacking.postCmd()
    elif opt == '5':
        input("请在运行之前确认已填写好./config/sql.txt配置文件\n按回车键继续...")
        mysql_hacking.mysqlBatch("./config/sql.txt")
    elif opt == '6':
        trojan.php_horse()
    elif opt == '7':
        fileche.fileCheck()
    elif opt == '8':
        hackcve.cve_send()
except:
    print("未知错误！！！")