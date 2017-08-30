#!/usr/bin/python -Es
# -*- coding: utf-8 -*-

# This file is part of PAMAC (PAM Access Control).
#
#    Copyright (C) 2017  Alexander Naumov <alexander_naumov@opensuse.org>
#
#    PAMAC is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    PAMAC is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with PAMAC.  If not, see <http://www.gnu.org/licenses/>.


import syslog, sys, os, re
import subprocess as sp

def id_info(logtype, user_id):
  try:
    return sp.Popen(['getent', 'passwd', user_id], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0].split(":")[0]
  except:
    syslog.syslog(logtype + "no info from getent... 'libc-bin' is not installed?")
    sys.exit(2)


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
    return sp.Popen(['loginctl', 'show-session', n], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0]
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
    info = sp.Popen(['loginctl'], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0]
  except:
    syslog.syslog(logtype + "'loginctl' is not there?")
    sys.exit(2)

  for i in info.split('\n')[1:-2]:
    if len(i) > 0: sessions.append([i for i in i.split(" ") if len(i) > 0])
    #print [i for i in i.split(" ") if len(i) > 0][0]

  for i in sessions:
    dic = {}
    dic['UID'] = i[1]
    for s in show_session(logtype, i[0]).split("\n")[:-1]:
      if re.search("Id=",s):         dic['Id'] = s.split('=')[1]
      if re.search("Name=",s):       dic['Name'] = s.split('=')[1]
      if re.search("Display=",s):    dic['Display'] = s.split('=')[1]
      if re.search("Remote=",s):     dic['Remote'] = s.split('=')[1]
      if re.search("Service=",s):    dic['Service'] = s.split('=')[1]
      if re.search("RemoteHost=",s): dic['RemoteHost'] = s.split('=')[1]
      if re.search("Type=",s):       dic['Type'] = s.split('=')[1]
      if re.search("State=",s):      dic['State'] = s.split('=')[1]
    LIST.append(dic)
  return LIST


if __name__ == '__main__':
  if (len(sys.argv) != 4):
    print ("usage: " + sys.argv[0] + " <HOST> + <LOGIN> + [ask | info]")
    sys.exit(1)

  logtype = "pamac(sshd): "
  if sys.argv[1]: rhost = sys.argv[1]
  if sys.argv[2]: rname = sys.argv[2]
  if sys.argv[3]: window = sys.argv[3]

  sessions = session_info(logtype)
  if not sessions:
    syslog.syslog(logtype + "'loginctl' returns nothing...")
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

        if window == "info":
          if n_conn == 0:
            print (sp.call('export DISPLAY=' + str(i['Display']) +
                   ' && /usr/bin/kdialog --msgbox "SSH connection has ended.\n\nHost: '+str(rhost) +'\nUser: ' +str(rname) +'"',
                   stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, shell=True))

        elif window == "ask":
          if n_conn == 1:
            active = 1
            print (sp.call('export DISPLAY=' + str(i['Display']) +
                   ' && /usr/bin/kdialog --msgbox "New SSH connection" --yesno "New SSH connection established. Allow it?\n\nHost: '
                   +str(rhost) + '\nUser: ' +str(rname)+ '\n"', stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, shell=True))
          else:
            print "0"
            sys.exit(0)

  if not active and window != "info":
    syslog.syslog(logtype + "can't find owner of X session and ask him => access granted")
    print "0"
    sys.exit(0)
