#!/usr/bin/python3 -Es
# -*- coding: utf-8 -*-

# This file is part of pam-accesscontrol.
#
#    Copyright (C) 2017,2018  Alexander Naumov <alexander_naumov@opensuse.org>
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


import syslog, sys, os, re
import subprocess as sp

def is_there(logtype, host, login, sessions):
  """
  It checks for other current SSH sessions of the user.
  Function returns integer - number of already created sessions.
  """
  item = 0
  for i in sessions:
     if 'RemoteHost' in i and 'Service' in i and 'Remote' in i and 'State' in i and 'Name' in i:
       if i['Remote'] == 'yes' and i['Service'] == 'sshd' and i['State'] != "closing":
         if host == i['RemoteHost'] and login == i['Name']:
           item = item+1
  if item > 1:
    syslog.syslog(logtype + "user:"+ str(login) + " host:" + str(host) + " is connected already to this host")
  return item


def show_session(logtype, n):
  try:
    return sp.getoutput("loginctl show-session " +str(n))
  except:
    syslog.syslog(logtype + "no info from loginctl... ")
    sys.exit(2)


def session_info(logtype):
  """
  It creates and returns list of dictonaries where each dictonary describes a session.
  """
  sessions = []
  LIST = []
  try:
    info = sp.getoutput('loginctl')
  except:
    syslog.syslog(logtype + "'loginctl' is not there?")
    sys.exit(2)

  for i in info.split('\n')[1:-2]:
    if len(i) > 0: sessions.append([i for i in i.split(" ") if len(i) > 0])

  for i in sessions:
    dic = {}
    dic['UID'] = i[1]
    for s in show_session(logtype, i[0]).split("\n"):
      if re.search("Id=",s):         dic['Id'] = s.split('=')[1]
      if re.search("Name=",s):       dic['Name'] = s.split('=')[1]
      if re.search("Display=",s):    dic['Display'] = s.split('=')[1]
      if re.search("Remote=",s):     dic['Remote'] = s.split('=')[1]
      if re.search("Service=",s):    dic['Service'] = s.split('=')[1]
      if re.search("RemoteHost=",s): dic['RemoteHost'] = s.split('=')[1]
      if re.search("Type=",s):       dic['Type'] = s.split('=')[1]
      if re.search("State=",s):      dic['State'] = s.split('=')[1]
      if re.search("Class=",s):      dic['Class'] = s.split('=')[1]
    LIST.append(dic)
  return LIST


def ask_window_is_there(host, login):
  """
  'loginctl list-sessions' shows new session for user X before user can answer via pam-accesscontrol's ask-window.
  Until now I didn't found some better solution then just to check for this window (by parsing for all processes).
  FIXME: looking for some better solution...
  """
  pattern = "/usr/bin/python3 -Es /usr/share/pam-accesscontrol/windows.py ssh-ask " + host + " " + login
  for i in sp.getoutput("ps aux").split("\n"):
      proc = re.search(pattern, i)
      if proc is not None:
          return True
  return False


def get_xauthority(name):
  for proc in sp.getoutput("pgrep " +str(name)).split("\n"):
    if len(proc)>0:
      try:
        int(proc)
        try:
          with open("/proc/" + str(proc) + "/environ" ,"r") as f: buf = f.read()
          if "XAUTHORITY" in buf:
            buf = buf.split("XAUTHORITY")[-1]
            buf = buf.split("}")[0]
            buf = buf[1:] + "}"
            if name == "lightdm": buf = buf[:-2]
            return str(buf)
        except:
          syslog.syslog(logtype + "can't open file /proc/" + str(proc) + "/environ ...")
      except:
        syslog.syslog(logtype + "no process found...")


if __name__ == '__main__':
  if (len(sys.argv) != 5):
    print ("usage: " + sys.argv[0] + " [True | False] <HOST> <LOGIN> [ssh-ask | ssh-info | access-denied-xorg]")
    sys.exit(1)

  DEBUG = False
  if sys.argv[1] == "True": DEBUG = True
  if sys.argv[2]: rhost  = sys.argv[2]
  if sys.argv[3]: rname  = sys.argv[3]
  if sys.argv[4]: window = sys.argv[4]

  if window == "access-denied-xorg": logtype = "pam-accesscontrol(Xorg): "
  else:                              logtype = "pam-accesscontrol(sshd): "

  if DEBUG:
    syslog.syslog(logtype + "DEBUG  = " + str(DEBUG))
    syslog.syslog(logtype + "HOST   = " + str(rhost))
    syslog.syslog(logtype + "NAME   = " + str(rname))
    syslog.syslog(logtype + "WINDOW = " + str(window))

  sessions = session_info(logtype)
  if not sessions:
    syslog.syslog(logtype + "'loginctl' returns nothing...")

  elif window == "access-denied-xorg":
    if DEBUG: syslog.syslog(logtype + "ACCESS-DENIED-XORG")
    for i in sessions:
      if i['Class'] == 'greeter':
        if DEBUG: syslog.syslog(logtype + "name = " + str(i['Name']))
        xauth = get_xauthority(str(i['Name']))
        if DEBUG: syslog.syslog(logtype + "XAUTHORITY = " + str(xauth))
        if DEBUG: syslog.syslog(logtype + "DISPLAY = " + str(i['Display']))

        print (sp.call('export DISPLAY=' + str(i['Display']) +
                   ' && export XAUTHORITY=' + str(xauth) +
                   ' && /usr/share/pam-accesscontrol/windows.py access-denied-xorg ' + str(rhost) + ' ' + str(rname) + ' &',
                     stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, shell=True))
        print ("0")
        sys.exit(0)
  else:
    n_conn = is_there(logtype, rhost, rname, sessions)
    syslog.syslog(logtype + "number of SSH sessions: "+str(n_conn))


  active = 0
  for i in sessions:
    if 'Remote' in i and 'Type' in i and 'UID' in i:
      if i['Remote'] == 'no' and i['Type'] == 'x11' and i['State'] == 'active' and i['Name'] != 'sddm' and 'Display' in i:
        try:
          os.setuid(int(i['UID']))
        except os.error:
          syslog.syslog(logtype + "can't change user")
          sys.exit(2)

        if ask_window_is_there(str(rhost), str(rname)):
          print ("1")
          sys.exit(1)

        if window == "ssh-info":
          if n_conn == 0:
            print (sp.call('export DISPLAY=' + str(i['Display']) +
                           ' && /usr/share/pam-accesscontrol/windows.py ssh-info ' + str(rhost) + ' ' + str(rname) + ' &',
                           stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, shell=True))

        elif window == "ssh-ask":
          if n_conn == 1:
            active = 1
            print (sp.call('export DISPLAY=' + str(i['Display']) +
                           ' && /usr/share/pam-accesscontrol/windows.py ssh-ask ' + str(rhost) + ' ' + str(rname),
                           stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, shell=True))
          else:
            print ("0")
            sys.exit(0)

  if not active and window != "ssh-info":
    syslog.syslog(logtype + "can't find owner of X session and ask him => access granted")
    print ("0")
    sys.exit(0)
