import paramiko
import re
import socket
import pandas as pd

class Mikrot(object):
    def __init__(self, ip='', sshuser='', sshpass='', sshtimeout=15, sshport='22', pallowagent=False, plookforkeys=False,
              encoding='ascii'):
        self.ip = ip
        self.sshuser = sshuser
        self.sshpass = sshpass
        self.sshtimeout = sshtimeout
        self.sshport = sshport
        self.pallowagent = pallowagent
        self.plookforkeys = plookforkeys
        self.encoding = encoding
        self.connectssh()
 #       status_msg = self.connectssh()
#        if status_msg != 'OK':
#            raise ValueError('Connection could not be established: %s' % status_msg)
        
                   
                   
    def _createssh(self):
        """
        Have no time to figure out what exact kex/key/ciph combo is required,
        so just copied ssh -Q output
        """
        paramiko.Transport._preferred_kex = ('diffie-hellman-group14-sha1',
                                            'diffie-hellman-group-exchange-sha1',
                                            'diffie-hellman-group-exchange-sha256',
                                            'diffie-hellman-group1-sha1',
                                            'diffie-hellman-group14-sha256',
                                            'diffie-hellman-group16-sha512',
                                            'diffie-hellman-group18-sha512',
                                            'ecdh-sha2-nistp256',
                                            'ecdh-sha2-nistp384',
                                            'ecdh-sha2-nistp521',
                                            'curve25519-sha256',
                                            'curve25519-sha256@libssh.org')
        paramiko.Transport._preferred_ciphers = ('3des-cbc',
                                                'aes128-cbc',
                                                'aes192-cbc',
                                                'aes256-cbc',
                                                'rijndael-cbc@lysator.liu.se',
                                                'aes128-ctr',
                                                'aes192-ctr',
                                                'aes256-ctr',
                                                'aes128-gcm@openssh.com',
                                                'aes256-gcm@openssh.com',
                                                'chacha20-poly1305@openssh.com')
        paramiko.Transport._preferred_keys = ('ssh-ed25519',
                                            'ssh-ed25519-cert-v01@openssh.com',
                                            'ssh-rsa',
                                            'ssh-dss',
                                            'ecdsa-sha2-nistp256',
                                            'ecdsa-sha2-nistp384',
                                            'ecdsa-sha2-nistp521',
                                            'ssh-rsa-cert-v01@openssh.com',
                                            'ssh-dss-cert-v01@openssh.com',
                                            'ecdsa-sha2-nistp256-cert-v01@openssh.com',
                                            'ecdsa-sha2-nistp384-cert-v01@openssh.com',
                                            'ecdsa-sha2-nistp521-cert-v01@openssh.com')

        mktssh = paramiko.SSHClient()
        mktssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return mktssh
      
    def _ssh_params_dict(self):
        dict = {
            'hostname': self.ip,
            'port': self.sshport,
            'username': self.sshuser,
            'password': self.sshpass,
            'timeout': self.sshtimeout,
            'allow_agent': self.pallowagent,
            'look_for_keys': self.plookforkeys
            }
        return dict
      
    def connectssh(self):
        self.conn_handler = self._createssh()
        ssh_params = self._ssh_params_dict()

        try:
            self.conn_handler.connect(**ssh_params)            
        except paramiko.AuthenticationException:
            raise ValueError('ERR_LOGIN')
        except paramiko.SSHException as sshException:
            raise ValueError('ERR_SSH_%s' % sshException)
        except socket.error as e:
            raise ValueError('ERR_SOCKET_%s' % e)
        except socket.timeout as e:
            raise ValueError('ERR_TIMEOUT_%s' % e)
        except Exception as e:
            raise ValueError('ERR_GENERAL: %s' % str(e))

      
    def send_command_oneway(self, command):
        _, _, _ = self.conn_handler.exec_command(command)
      
    def get_command_output(self, command):
        _, output, _ = self.conn_handler.exec_command(command)
        return output.readlines()
      
    def close_session(self):
        self.send_command_oneway('quit')
        self.conn_handler.close()
      
    
    def get_keyval_dict(self, command, keycol, valuecol, idxcol='#'):
        """
        Right now it works only with numeric data in columns.
        Goota add digits=True/False later
        """
        listoflines = self.get_command_output(command)
        head_line = [idx for idx,s in enumerate(listoflines) if idxcol in s][0]
        validx = listoflines[head_line].find(valuecol)
        keyidx = listoflines[head_line].find(keycol)
        outdict = {}
        idx = ''
        for line in listoflines:   
            if re.search(r'\d', line[validx:validx+1]):  
                if re.search(r'\d', line[keyidx:keyidx+1]):
                    idx = line[keyidx:].split(' ')[0]
                    
                if idx not in outdict:
                    outdict[idx] = line[validx:].split(' ')[0]
                else:
                    outdict[idx] += ','+line[validx:].split(' ')[0]
        return outdict
      
    def get_val_list(self, command, valuecol, digits=True):
        vallist = []
        listoflines = self.get_command_output(command)
        validx = max([x.find(valuecol) for x in listoflines])
        for line in listoflines:  
            if digits:
                if (re.search(r'^\w', line[validx:]) and not re.search(r'^%s' % valuecol, line[validx:]) \
                    and re.search(r'\d', line[validx:validx+1])):  
                    vallist.append(line[validx:].split(' ')[0])
            else:
                if (re.search(r'^\w', line[validx:]) and not re.search(r'^%s' % valuecol, line[validx:])):
                    vallist.append(line[validx:].split(' ')[0]) 
            """
            To add some beauty it should looks like:
            if (re.search(r'^\w', line[validx:]) and not re.search(r'^%s' % valuecol, line[validx:])) or \
            (re.search(r'^\w', line[validx:]) and not re.search(r'^%s' % valuecol, line[validx:]) and \
             digits and re.search(r'\d', line[validx:validx+1])):
                vallist.append(line[validx:].split(' ')[0]) 
            But no luck
            """
        return vallist
    
    def get_table(self, command, idxcol='#'):
        """
        Assuming that normally index coulmn is #
        """
        listoflines = self.get_command_output(command)
        data = []
        head_line = [idx for idx,s in enumerate(listoflines) if idxcol in s][0]
        cols = list(filter(None, listoflines[head_line].rstrip().split(' ')))
        for lineidx,line in enumerate(list(filter(None, [x.rstrip() for x in listoflines[head_line+1:]]))):
            valdict = {}
            for idx,column in enumerate(cols):
                if column == idxcol:
                    currvalue = line[:listoflines[head_line].find(column)+1].replace(' ', '')
                    if currvalue == '':
                        currvalue = listoflines[head_line+lineidx][:listoflines[head_line].find(column)+1].replace(' ', '')
                    valdict[column] = currvalue
                elif idx == len(cols) - 1:
                    valdict[column] = line[listoflines[head_line].find(column):].split(' ')[-1]
                else:
                    valdict[column] = line[listoflines[head_line].find(column):].split(' ')[0]
            data.append(valdict)
        df = pd.DataFrame(data,columns=cols)
        df.drop_duplicates(subset=idxcol, keep="last", inplace=True)
        return df.reset_index(drop=True)
