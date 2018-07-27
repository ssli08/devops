#!/usr/bin/python
#!coding=utf-8
import os
import json
import logging.handlers
import traceback


#checkItems = {'GeneralParam':{}, 'AsteriskParam':{}, 'KamailioParam':{}, 'McuParam':{}}
#items = list()
count = 0
#string = '.'*20
def logger(filename):
    def decorator(func):
        def inner(*args, **kwargs):
            ERROR_LOG_SIZE = 10*1024*1024
            logFormatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
            logger = logging.getLogger('')
            logger.setLevel(logging.DEBUG)
            logFileHandler = logging.handlers.RotatingFileHandler(filename,
                            mode='a', maxBytes=ERROR_LOG_SIZE, backupCount=2, encoding=None)
            logFileHandler.setFormatter(logFormatter)
            logger.addHandler(logFileHandler)
            try:
                result = func(*args, **kwargs)
                logger.info('function name is %s, result: %s'%(func.__name__, result))
                
            except:
                logger.error(traceback.format_exc())
        return inner
    return decorator



def excuteCommand(cmd, detail=None):
    global count
    count+=1

    args, result = readParam(cmd)
    if detail:
	#args, result = readParam(cmd)
       	print '%s - %-100s[%s]'%(count,cmd, higLight(args))
	print 'Detail:\n%s'%result
    else:
        #status = subCmd(cmd)
        #if status:
        if result is not None:
		result = 'Pass'
        else:
		result = 'Failed'
    	print '%s - %-100s[%s]'%(count, cmd, higLight(result))
    return result
             
def fileExist(path):
    data = dict()
    global count
    count+=1
    if os.path.isfile(path):
        checkPermission(path)
        changeOwner(path)

	status = 'Pass'
    else:
	status = 'Failed'
    print '%s - %-100s[%s]'%(count, path, higLight(status))
    return

#def subCmd(args):
#    import subprocess
#    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
#    errMsg = p.stderr.read()
#    #print errMsg
#    if errMsg:
#        return False
#    else:
#        return True

def dirExist(path):
    data = dict()
    global count
    count+=1
    if os.path.isdir(path):
	result = 'Pass'
    else:
	result = 'Failed'
    print '%s - %-100s[%s]'%(count, path, higLight(result))
    return
    
def readParam(cmd):
    import subprocess

    '''
    get state and result for each command provided by the 'list' in 'main' function
    '''

    publicIP, privateIP, region = getHostIP()
    p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    result = p.stdout.read()

    if ('GS_ENV_PRIVATE_IPADDRESS' or 'GS_ENV_PUBLIC_IPADDRESS') in cmd and result:
        cf_public, cf_private = CheckLocalConfEnv()
        if cf_public == publicIP and cf_private == privateIP:
            #print 'public ipaddr is %s, private ip %s'%(publicIP, privateIP)
            #print 'cf_public ip %s, cf_private ip %s' %(cf_public, cf_private)
            return 'Pass', result
        else:
            #print 'public ipaddr is %s, private ip %s'%(publicIP, privateIP)
            #print 'cf_public ip %s, cf_private ip %s' %(cf_public, cf_private)

            return 'Failed', None
    elif 'python' in cmd:
        return 'Pass', p.stderr.read()
    elif 'jdk' in cmd:
        return 'Pass', p.stderr.read()   
    elif 'cat' in cmd: 
        if 'unlimited' in result:
            return 'Pass', result
        else:
            return 'Failed', None
    elif result:
        return 'Pass', result
    else:
        return 'Failed',None
        
def changeOwner(filename):
    '''
    change the owner of gs_logrotate to 'root'.
    '''
    if 'gs_logrotate' in filename:
        if os.stat(filename).st_uid != 0:
            os.chown(filename, 0, 0)
            checkPermission(filename)
    else:
        pass        
    return True
        
def checkPermission(filename):
    import stat

    '''
    Add excute permission for rc.local on CentOS7.2, so that autostart script takes effect.
    '''
    
    perm = oct(os.stat(filename).st_mode)[-3:]
    if perm == 755:
        return 'Pass'
    else:
        try:
            os.chmod(filename, stat.S_IRWXU+stat.S_IRGRP+stat.S_IXGRP+stat.S_IROTH+stat.S_IXOTH)
        except Exception,e:
            return False, e
        return 'Fail'
    return True              

def higLight(args):
    if args == 'Pass':
        return '\033[1;32;40m %s \033[0m' %args
    elif args == 'Failed':
        return '\033[1;31m %s \033[0m' %args
    else:
        return '\033[1;32;40m %s \033[0m' %args

def urlRequest(url):
	import urllib2
	try:
		result = urllib2.urlopen(url, timeout=2).read()
	except Exception,e:
		return 
	return result
# @logger('/tmp/deployCheck.log')
def getHostIP():
    import urllib2
    localURL = 'http://169.254.169.254/latest/meta-data/local-ipv4'
    amazonURL = 'http://169.254.169.254/latest/meta-data/public-ipv4' 
    idcURL = 'http://ip.42.pl/raw'
    #regionCmd = 'curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone|sed "s/[a-z]$//"'
    regionCmd = 'http://169.254.169.254/latest/meta-data/placement/availability-zone'

    output = os.popen('ifconfig |grep ^e|awk -F: "NR==1 {print \$1}"').read().strip('\n')
    privateCMD = "ifconfig %s|awk 'NR==2 {print $2}'|awk '{print $1}'"%output
    

    publicIP = urlRequest(amazonURL)
    if publicIP:
            privateIP = urlRequest(localURL)
            region = urlRequest(regionCmd)[:-1]
    else:
	    publicIP = urlRequest(idcURL)
            privateIP = os.popen(privateCMD).read().strip('\n')
            region = 'IDC'

    return publicIP, privateIP, region

def CheckLocalConfEnv(cfile='/data/conf/local_env.cfg'):
    import ConfigParser
    cf = ConfigParser.ConfigParser()
    cf.read(cfile)
    section = cf.sections()
    #items = cf.items(section[0])
    cf_private = cf.get(section[0], 'gs_env_private_ipaddress')
    cf_public = cf.get(section[0], 'gs_env_public_ipaddress')
    return cf_public, cf_private 

@logger('/tmp/deployCheck.log')
def remoteExcute(host,command, user='ec2-user',pwd='ec2@gs.com'):
    import paramiko
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host,26222,user,pwd,timeout=10)
    (stdin,stdout,stderr) = ssh.exec_command(command)
    print  stdout.read()
    ssh.close()

def dnsQuery(domain=''):
    '''
    dig tool for domain name lookup
    '''
    cmd = 'dig %s|grep %s' %(domain,domain)
    args, result = readParam(cmd)
    print '- %-100s[%s]'%(cmd, higLight(args))
    print 'Detail:\n%s'%result.split('\t')[-1]
    return 

def javaCheck():
    global count
    count += 1
    try:
        javaPids = os.popen('pidof java').read().split()
        jdk = [os.readlink('/proc/%s/exe'%i) for i in javaPids if i == i ]
        cmd = jdk[0]+' '+'-version'
        args, result = readParam(cmd) 
    except Exception,e:
        print traceback.format_exc(e)
    print '%s - %-100s[%s]'%(count, cmd, higLight(args))
    print 'Detail:\n%s'%result.split('\t')[-1]
    return

@logger('/tmp/deployCheck.log')
def main(args):
    publicIP, privateIP, region = getHostIP()
#     checkItems['KamailioParam'][ip] = list()
#     checkItems['KamailioParam'][ip].append(items)
#     print checkItems
    
    if args == 'asterisk':
        print '%-10s\n[%s]-%s(%s)'%('Asterisk',higLight(region), publicIP, privateIP)

        dirs = ['/data', '/data/conf', '/data/video', '/data/corefiles']
        files = ['/etc/rsyslog.d/gs_logrotate','/data/conf/local_env.cfg','/etc/rc.d/rc.local','/opt/sipChecker/startSip.py']

        processList = ['systemctl status crond','ps -ef|grep -i startsip.py', 'ps -ef|grep zabbix_agentd','ps -ef|grep asterisk','ps -ef|grep backup']
	cmdList = ['rpm -qa|grep ntpdate','python -V']
        confList = ['grep "^SERV_TYPE" /opt/sipChecker/startSip.py','grep -i corefiles /etc/rc.d/rc.local','grep -i startSip.py /etc/rc.d/rc.local','grep -i zabbix_agentd /etc/rc.d/rc.local',\
'crontab -l|grep ntpdate','crontab -l|grep gs_logrotate','crontab -l|grep client.py','grep nameserver /etc/resolv.conf','grep corefiles /proc/sys/kernel/core_pattern',\
'cat /proc/$(pidof asterisk)/limits|egrep -i "core|open"','grep -A 5 unlimited /etc/security/limits.conf','grep 102400 /etc/security/limits.conf',\
'egrep -i "GS_ENV_PRIVATE_IPADDRESS|GS_ENV_PUBLIC_IPADDRESS|GS_ENV_SERVICE_ELB|GS_AST_MAX_BANDWIDTH|GS_AST_MAX_CONFS|GS_AST_MAX_CALLS" /data/conf/local_env.cfg']
        print higLight('\nDirectoryCheck')
        for i in dirs:
            dirExist(i)
        print higLight('\nFileExistCheck')
        for i in files:
                fileExist(i)
        print higLight('\nProcessCheck')
        for i in processList:
            excuteCommand(i)
	print higLight('\nGeneralCheck')
	for i in cmdList:
            excuteCommand(i, detail='a')
        print higLight('\nConfCheck')
        for i in confList:
            excuteCommand(i,detail='a')

    elif args == 'kamailio':
	print '%-10s\n[%s]-%s(%s)'%('Kamailio',higLight(region), publicIP, privateIP)

        dirs = ['/data', '/data/conf','/data/corefiles']
        files = ['/etc/rsyslog.d/gs_logrotate','/etc/rsyslog.d/xserver_logs.conf','/data/conf/local_env.cfg','/etc/rc.d/rc.local','/opt/sipChecker/startSip.py']
        
        processList = ['systemctl status crond','ps -ef|grep -i startsip.py', 'ps -ef|grep zabbix_agentd', '/opt/script/xserver status', 'ps -ef|grep redis',\
'ps -ef|grep backup','ps -ef|grep inotify']

        cmdList = ['rpm -qa|grep ntpdate', 'python -V', 'pip list|grep MySQL-python', 'pip list|grep cryptography', 'pip list|grep boto3']

        confList = ['grep -i corefiles /etc/rc.d/rc.local','grep -i startSip.py /etc/rc.d/rc.local','egrep -i "zabbix|backup" /etc/rc.d/rc.local','crontab -l|grep ntpdate',\
'crontab -l|grep gs_logrotate','cat /proc/$(pidof kamailio|awk "{print \$NF}")/limits|egrep -i "core|open"', 'cat /proc/$(pidof conference)/limits|egrep -i "core|open"',\
'cat /proc/$(pidof conference)/limits|egrep -i "core|open"','grep "^SERV_TYPE" /opt/sipChecker/startSip.py','grep corefiles /proc/sys/kernel/core_pattern','grep -A 5 unlimited /etc/security/limits.conf',\
'grep 102400 /etc/security/limits.conf','grep "local0|local1" /etc/rsyslog.conf','egrep -i "GS_ENV_PRIVATE_IPADDRESS|GS_ENV_PUBLIC_IPADDRESS" /data/conf/local_env.cfg',\
'grep GS_ENV_IPVT_USE_ELB=1 /data/conf/local_env.cfg']

	print higLight('\nDirectoryCheck')
        for i in dirs:
            dirExist(i)
	print higLight('\nFileExistCheck')
	for i in files:
		fileExist(i)
        print higLight('\nProcessCheck')
        for i in processList:
            excuteCommand(i)
	print higLight('\nGeneralCheck')

	for i in cmdList:
	    excuteCommand(i, detail='a')

	print higLight('\nConfCheck')
        for i in confList:
	    excuteCommand(i, detail='a')
    elif args == 'mcu':
        print '%-10s\n[%s]-%s(%s)'%('MCU',higLight(region), publicIP, privateIP)

	files = ['/etc/rc.d/rc.local','/etc/logrotate.d/mcu_log','/home/ec2-user/mcuChecker.sh','/etc/rsyslog.d/60.mcu.conf']
        dirs = ['/data', '/data/conf']
	cmdList = ['rpm -qa|grep ntpdate', 'nvidia-smi', 'ls -ld /usr/local/cuda-7.5/']
	processList = ['systemctl status crond', 'ps -ef|grep gs_avs']
	confList = ['crontab -l |grep mcuChecker','crontab -l|grep gs_logrotate', 'crontab -l|grep client.py','grep core_pattern /etc/rc.d/rc.local','grep init.sh /etc/rc.d/rc.local',\
'cat /proc/$(pidof gs_avs)/limits|egrep -i "core|open"','grep zabbix_agentd /etc/rc.d/rc.local','grep corefiles  /proc/sys/kernel/core_pattern','strings /proc/`pidof gs_avs`/environ|grep -i tc',\
'egrep "local0|local1" /etc/rsyslog.conf']

	print higLight('\nDirectoryCheck')
        for i in dirs:
            dirExist(i)
        print higLight('\nFileExistCheck')
        for i in files:
                fileExist(i)
        print higLight('\nProcessCheck')
        for i in processList:
            excuteCommand(i)
        print higLight('\nGeneralCheck')
        for i in cmdList:
            excuteCommand(i, detail='a')

        print higLight('\nConfCheck')
        for i in confList:
            excuteCommand(i, detail='a')

    elif args == 'mysql':
        print '%-10s\n[%s]-%s(%s)'%('MySQL',higLight(region), publicIP, privateIP)

        cmdList = ['rpm -qa|grep ntpdate']
        processList = ['ps -ef|grep zabbix', 'ps -ef|grep mysqld', 'ps -ef|grep 6379', 'ps -ef|grep 6381']
        confList = ['crontab -l |grep mysqldump', 'crontab -l|grep /xtraBackup', 'crontab -l|grep ntpdate']

        print higLight('\nProcessCheck')
        for i in processList:
            excuteCommand(i)
        print higLight('\nGeneralCheck')
        for i in cmdList:
            excuteCommand(i, detail='a')

        print higLight('\nConfCheck')
        for i in confList:
            excuteCommand(i, detail='a')
    elif args == 'web':
        print '%-10s\n[%s]-%s(%s)'%('Web',higLight(region), publicIP, privateIP)
        
        files = ['/etc/rsyslog.d/nginx_logrotate', '/etc/rc.d/rc.local', '/data/conf/web_local_env.cfg', '/data/backup/backup.sh']
        cmdList = ['rpm -qa |grep ntpdate', 'java -version']

        processList = ['systemctl status crond', 'ps -ef|grep zabbix', 'ps -ef|grep ipv_web', 'ps -ef|grep meeting_web', 'ps -ef|grep meetings.ipvideotalk.com', 'ps -ef|grep admin.ipvideotalk.com',\
'ps -ef|grep meetings_log', 'ps -ef|grep nginx', 'ps -ef|grep backup']

        confList = ['crontab -l |grep tzUpdater', 'crontabl -l |grep check', 'crontab -l|grep nginx_logrotate', 'grep nginx /etc/rc.d/rc.local', 'grep deploy.sh /etc/rc.d/rc.local', \
'grep zabbix_agentd /etc/rc.d/rc.local', 'grep backup /etc/rc.d/rc.local', 'grep storage /data/conf/web_local_env.cfg']

        print higLight('\nFileExistCheck')
        for i in files:
                fileExist(i)

        print higLight('\nProcessCheck')
        for i in processList:
            excuteCommand(i)
        print higLight('\nGeneralCheck')
        for i in cmdList:
            excuteCommand(i, detail='a')

        print higLight('\nConfCheck')
        for i in confList:
            excuteCommand(i, detail='a')
        javaCheck()
    elif args == 'task':
        print '%-10s\n[%s]-%s(%s)'%('Task',higLight(region), publicIP, privateIP)
    
        files = ['/etc/rc.d/rc.local', '/data/conf/web_local_env.cfg', '/data/backup/backup.sh']
        cmdList = ['rpm -qa |grep ntpdate', 'java -version']

        processList = ['systemctl status crond', 'ps -ef|grep zabbix', 'ps -ef|grep ipvt_task', 'ps -ef|grep meeting_task', 'ps -ef|grep ipv_mail_task', 'ps -ef|grep meeting_mail_task', \
'ps -ef|grep sqs_processor', 'ps -ef|grep main.py', 'ps -ef|grep backup']
        confList = ['crontab -l |grep tzupdater.jar', 'grep deploy.sh /etc/rc.d/rc.local', 'grep main.py /etc/rc.d/rc.local', 'grep backup /etc/rc.d/rc.local', \
'egrep -i "mail|storage" /data/conf/web_local_env.cfg']
        
        print higLight('\nFileExistCheck')
        for i in files:
                fileExist(i)

        print higLight('\nProcessCheck')
        for i in processList:
            excuteCommand(i)

        print higLight('\nGeneralCheck')
        for i in cmdList:
            excuteCommand(i, detail='a')

        print higLight('\nConfCheck')
        for i in confList:
            excuteCommand(i, detail='a')
        javaCheck()
    elif args == 'dns':
        print '%-10s\n[%s]-%s(%s)'%('DNS',higLight(region), publicIP, privateIP)
        
        cmdList = ['rpm -qa|grep ntpdate']
        processList = ['ps -ef|grep zabbix_agentd', 'ps -ef|grep named']
        domainList = ['mysql.gs', 'sip.redis.gs','web.redis.gs', 'ipv.private.com','account.private.com','meetings.private.com', 'pro.ipvideotalk.com','xmeetings.ipvideotalk.com','api.ipvideotalk.com',\
'admin.ipvideotalk.com', 'account.ipvideotalk.com','style.ipvideotalk.com']

        print higLight('\nProcessCheck')
        for i in processList:
            excuteCommand(i)

        print higLight('\nGeneralCheck')
        for i in cmdList:
            excuteCommand(i, detail='a')
        print higLight('\nDomainCheck')
        for i in domainList:
            dnsQuery(i)    
        
    #print json.dumps(items,indent=2)    
    return True
                    
      

if __name__ == '__main__':
    import argparse
    import sys
    a, b = sys.argv
    if b == 'kamailio':
        main('kamailio')
    elif b == 'asterisk':
        main('asterisk')
    elif b == 'mcu':
        main('mcu')
    elif b == 'web':
        main('web')

    elif b == 'database' or b == 'mysql':
        main('mysql')

    elif b == 'task':
        main('task')
    else:
        main('dns')
    #javaCheck()
    #remoteExcute('183.136.237.35', main('asterisk'))
