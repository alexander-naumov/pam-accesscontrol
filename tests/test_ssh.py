#!/usr/bin/env python3

# This file is part of pam-accesscontrol.
#
#    Copyright (C) 2019  Alexander Naumov <alexander_naumov@opensuse.org>
#
#    PAM-ACCESSCONTROL is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    PAM-ACCESSCONTROL is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with PAM-ACCESSCONTROL.  If not, see <http://www.gnu.org/licenses/>.

from scp import SCPClient
import os, sys
import argparse
import paramiko
import subprocess as sp


def cmd_show_remote_list(LIST):
  """
  """
  print("------------------------------------------------------------------------------------------------------")
  print("SHA256                                                           | FILES on " + str(hostname))
  print("------------------------------------------------------------------------------------------------------")
  for i in LIST.items():
      print(str(i[1] + " | " + i[0]))
  sys.exit(1)


def sha_check(SHA256, FILE_R, FILE_L):
  """
  """
  try:
    sha = sp.getoutput(sp.getoutput("which sha256sum") + " " + FILE_L).split("  ")[0]
    print(sha + " : " + FILE_L + " : ", end = '')
    if sha == SHA256:
        print("OK")
        return True
    else:
        print("FAILED")
        return False
  except:
    print("Something goes wrong! FILE: " + FILE_L)
    return False


def test_sha_error(FILE):
  """
  """
  out = sp.getoutput("echo ERROR >> " + FILE)


p = argparse.ArgumentParser(
     formatter_class=argparse.RawDescriptionHelpFormatter,
     epilog = '''
     ''')

p.add_argument('-host',
     required=True,
     dest='hostname',
     help="IP address of the target host")

p.add_argument('-user',
     required=True,
     dest='user',
     help="username of the target host")

p.add_argument('-port',
     required=False,
     dest='port',
     help="Port number of the SSH server")

p.add_argument('-timeout',
     required=False,
     dest='timeout',
     help="Timeout for the SSH connection")

p.add_argument('-ssh-path',
     required=False,
     dest='ssh_key',
     help="PATH of the SSH key (incl. filename)")

p.add_argument('-local-dir',
     required=True,
     dest='local_dir',
     help="Where DATA should be saved")

p.add_argument('-remote-dir',
     required=True,
     dest='remote_dir',
     help="Location of the DATA you need to copy")

p.add_argument('-regex',
     required=False,
     dest='regex',
     help="Regex templeate for the remote DATA")

p.add_argument('-debug',
     required=False,
     dest='DEBUG',
     help="Enable or disable DEBUG info")

p.add_argument('-command',
     required=False,
     dest='command',
     help="some help functions")

ARG = p.parse_args()

hostname  = ARG.hostname
user      = ARG.user
local_dir = ARG.local_dir
remote_dir= ARG.remote_dir

port    = 22                               if not ARG.port    else ARG.port
timeout = None                             if not ARG.timeout else str(ARG.timeout)
ssh_key = '/home/' + user + '/.ssh/id_rsa' if not ARG.ssh_key else ARG.ssh_key
regex   = '*'                              if not ARG.regex   else ARG.regex
DEBUG   = False                            if not ARG.DEBUG   else True
command = 'nothing'                        if not ARG.command else ARG.command


try:
  sshcon   = paramiko.SSHClient()  # will create the object
  sshcon.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # no known_hosts error
  sshcon.connect(hostname, port, user, ssh_key, timeout=timeout) # no passwd needed

except paramiko.ssh_exception.AuthenticationException:
  print("Authentication failed, please verify your credentials: %s")
  sys.exit(1)

except paramiko.ssh_exception.BadAuthenticationType:
  print("Unable to establish SSH connection: %s" % sshException)
  sys.exit(1)

except paramiko.ssh_exception.BadHostKeyException as badHostKeyException:
  print("Unable to verify server's host key: %s" % badHostKeyException)
  sys.exit(1)

except paramiko.ssh_exception.NoValidConnectionsError:
  sys.exit(1)

except paramiko.ssh_exception.SSHException as e:
  print(e)
  sys.exit(1)

except Exception as e:
  print("Can't establish SSH connection to " + hostname)
  print(e)
  sys.exit(1)

try:
  CMD = sp.getoutput('which sha256sum') + " " + remote_dir + "/" + regex
  ssh_stdin, ssh_stdout, ssh_stderr = sshcon.exec_command(CMD)
except:
  print("Something goes wrong by getting data from a remote system...")


LIST = {}
for i in ssh_stdout.readlines():
    SHA, FNAME = i[:-1].split("  ")
    LIST[FNAME] = SHA


if command == "show-remote-list": cmd_show_remote_list(LIST)

with SCPClient(sshcon.get_transport()) as scp:
  for FILE in LIST.items():
    FILE_R = FILE[0]
    FILE_L = local_dir + "/" + FILE[0].split("/")[-1]
    scp.get(FILE_R)

    if command == "test_sha_error": test_sha_error(FILE_L)

    if sha_check(FILE[1], FILE_R, FILE_L):
      sshcon.exec_command("rm " + FILE_R)
    else:
      print("Wrong sha256sum! File: " + FILE_R)

sshcon.close()
