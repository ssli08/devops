#!/usr/bin/python
#coding=utf-8
import paramiko
import os
import traceback
import getpass

class Runner(object):
    def __init__ (self, host, password, port=26222,user='ec2-user'):
        self.host = host
        self.password = password
        self.port = port
        self.username = user
        self.remote_path = '.remrunner'
        self.f = ''
    #@staticmethod
    def fileProgress(self, xfer, to_be_xfer):
        "display the file transfer progress bar.."
        print self.f +  " transferred: {0:.0f} %".format((xfer / to_be_xfer) * 100)
        return

    def close(self):
	'''
	close the sftp & ssh connection and clean the execution directorory & files
	'''
        ssh, sftp = self.paramikoExec()
        if sftp:
	    for i in sftp.listdir(self.remote_path):
	    	sftp.remove(os.path.join(self.remote_path, i))
	    #sftp.rmdir(self.remote_path)
            sftp.close()
        return True

    def paramikoExec(self):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.host, self.port, self.username, self.password, timeout=10)
            #stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10, get_pty=True)
            #exit_code = stdout.channel.recv_exit_status()
            sftp = ssh.open_sftp()
        except Exception,e:
            print traceback.format_exc(e)

        return ssh, sftp
    
    def run(self, local_script, sudo=False, opts=None):
	'''
        Install local script to remote server
	'''
	ssh, sftp = self.paramikoExec()

        try:
	    #help(sftp)
	    stat = sftp.stat(self.remote_path)
	except Exception, e:
      	    sftp.mkdir(self.remote_path, mode=0o700)
        #sftp.put(local_script,os.path.join(self.remote_path, local_script),callback=None)
        self.f = local_script.split('/')[-1]
        sftp.put(local_script,os.path.join(self.remote_path,local_script),callback=self.fileProgress)
        sftp.chmod(os.path.join(self.remote_path, local_script), 0o700)

        '''
        Execute command on the remote server
	'''
        if not os.path.exists(local_script):
            raise IOError ('No such file %s'%local_script)
        
        cmd = os.path.join(self.remote_path,local_script.split('/')[-1])
        if sudo:
            cmd = 'sudo' + ' '+ cmd
        if opts:
            cmd = cmd + ' ' + opts
	stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10, get_pty=True)
	exitStatus  = stdout.channel.recv_exit_status()
	out = stdout.read()
	err = stderr.read()
	ssh.close()

	return exitStatus, out, err

    @staticmethod	
    def LocalCFG_Read(inventory,role):
    	import ConfigParser
    	cf = ConfigParser.ConfigParser()
    	cf.read(inventory)
    	itemList = cf.options(role)
    	return itemList   

if __name__ == "__main__":
    import sys
    passwd = getpass.getpass('Password:')
    
    path = '/etc/ansible'
    origin, ansibleFile, role = sys.argv
    inventory = os.path.join(path,ansibleFile)
    items = Runner.LocalCFG_Read(inventory,role)

    for host in items:
    	remoteRun = Runner(host, passwd,port=22, user='root')
	exit_code, out, err = remoteRun.run('./deployCheck.py', opts=role)
    	print  out
    remoteRun.close()

