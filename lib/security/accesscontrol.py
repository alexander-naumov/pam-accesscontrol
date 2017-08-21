import subprocess as sp
import syslog, os, sys, re, datetime, glob

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


def create_log(logtype, SERVICE, rhost, user, mode, msg):
  """
  It creates new entry in the logfile. The format of log-entry is:
  date <SPACE> current time <TAB> service name <TAB> rule <TAB> username@hostname <TAB> some_text <newline>
  """
  now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  FILE = '/var/log/pamac-' + str(datetime.datetime.now().strftime("%Y-%m")) + '.log'

  if not rhost: rhost = "localhost"
  try:
    fd = open(FILE, 'a+')
    fd.write("%s%s%s%s%s\n" % (now.ljust(23), SERVICE.ljust(7), str(mode).ljust(10), (str(user) + "@" + str(rhost)).ljust(50), msg.ljust(15)))
    fd.close()
  except:
    syslog.syslog(logtype + "can't open/write logfile " + FILE)


def check_log(logtype, SERVICE, rhost, user):
  """
  This funtion can be used to figure out is the current SSH session last on or not.
  In fact we have mulisessions (sessions inside other sessions), but we should be
  notified only about last one.
  """
  FILE = '/var/log/pamac-' + str(datetime.datetime.now().strftime("%Y-%m")) + '.log'

  try:
    fd = open(FILE, 'a+')
    logfile = reversed(fd.read().split("\n"))
    fd.close()
  except:
    syslog.syslog(logtype + "can't open/read logfile " + FILE)

  for l in logfile:
    if len(l) > 0:
      L = [L for L in l.split(" ") if len(L)>0 and re.search('[a-zA-Z]', L)]
      if L[2] == str(user + "@" + rhost):
        if L[4] in ["new", "granted"]:
          syslog.syslog(logtype + "closing session - user:" + str(user) + " host:"+str(rhost))
          create_log(logtype, SERVICE, rhost, user, L[1], "closing session")
          if L[1] == "GUI":
            return 1
          else:
            return 0
  return 0


def ids(LIST):
  return [L for L in LIST.split(",") if len(L)>0]

def configuration(logtype):
  conf_files = sorted(glob.glob('/etc/pamac.d/*.conf'))
  all_conf = []
  if conf_files:
    for cur_file in conf_files:
      try:
        with open(cur_file, 'r') as fd:
          conf = fd.read().upper().split("\n")
          all_conf = all_conf + conf
      except:
        syslog.syslog(logtype + "can't open file: " + curfile)
  return all_conf


def get_default(logtype):
  """
  It reads the config file, parse it and tries to find 'DEFAULT' and
  'DEBUG' values.

  DEFAULT:
  This value will be interpreted as a default behavior for the NOT defined
  users or groups. Keep in mind, it supports only two modes CLOSE and OPEN.
  If you define DEFAULT rule many times, it will take value of the last one.
  ATENTION: if DEFAULT rule will be not set in a config file, it will set
  to 'CLOSE' automaticaly.

  DEBUG:
  Same for 'DEBUG'. Default = False and False means that only most important
  events will be logged. Default = True will turn ALL events on. Make sence
  for debugging, but can be confused for users/admins.
  """
  DEBUG   = False
  DEFAULT = 'CLOSE'

  for line in configuration(logtype):
    if line[:8] == "DEFAULT:":
      if line.split(":")[1] in ['CLOSE', 'OPEN']:
        syslog.syslog(logtype + "default access rule: " + line.split(":")[1])
        DEFAULT = line.split(":")[1]
      else:
        syslog.syslog(logtype + "default: CLOSE")

    if line[:6] == "DEBUG:":  DEBUG = line.split(":")[1]

  if DEBUG == 'TRUE': DEBUG = True
  else:               DEBUG = False
  return DEFAULT, DEBUG


def config_parser(logtype, SERVICE, DEBUG):
  """
  It reads and parses the config file and returns the LIST of the correctly
  defined rules. Broken rules will be just ignored (for security reason).
  """
  rules = []
  for rule in [c for c in configuration(logtype) if len(c) > 3 and c[:3] == SERVICE]:
    dic = {}
    if len(rule.split(" ")) != 4:
      if DEBUG: syslog.syslog(logtype + "broken rule, wrong number of options... skipping: " +str(rule))

    elif rule.split(" ")[1] not in ['OPEN', 'CLOSE', 'GUI','NUMBER']:
      if DEBUG: syslog.syslog(logtype + "second parameter is broken: " +str(rule))

    elif rule.split(" ")[2] not in ['USER', 'GROUP']:
      if DEBUG: syslog.syslog(logtype + "third parameter is broken: " +str(rule))

    else:
      dic['OPTION'] = str(rule.split(" ")[1] + " " + rule.split(" ")[2])
      dic['LIST'] = ids(rule.lower().split(" ")[3])
      rules.append(dic)
  return rules


def number_of_logged_already(logtype, login, group, DEBUG):
  """
  Use this function to figure out number of already logged users which
  belong to the 'group'. Users with the same login (name) are not counted,
  i.e. one user can create n sessions and in this case we still have ONE user.
  It takes 'login' as a parameter to be able to calculate number of users
  after creating this new session.
  """
  item = 0
  USERS = []
  users_in_system = sp.Popen(["/usr/bin/who"],stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0].split("\n")
  for users in users_in_system[:-1]:
    USERS.append([user for user in users.split(" ") if len(user)>0][0])

  if DEBUG: syslog.syslog(logtype + "USERS list: " + str(USERS))
  USERS.append(login)
  USERS = dict(zip(USERS, USERS)).values() #delete same users: bob,tom,tom,tom => bob,tom
  if DEBUG: syslog.syslog(logtype + "USERS list after compression: " + str(USERS))

  for U in USERS:
    if U in get_users_from_group(group):
      item = item+1
  if DEBUG: syslog.syslog(logtype + "number of users (group '" + str(group) + "') after new connection: " + str(item))
  return item


def check_number_in_group(logtype, login, LIST, DEBUG):
  """
  It checks LIST of NUMBER rule to make a decision about creating new session.
  """
  allow = []
  for L in LIST:
    if len(L.split(":")) != 2:
      if DEBUG: syslog.syslog(logtype + "wrong defined rule NUMBER '" + str(L) + "'... skipping")
    else:
      if login in get_users_from_group(L.split(":")[0]):
        try:
          if int(L.split(":")[1]) < int(number_of_logged_already(logtype, login, L.split(":")[0], DEBUG)):
            if DEBUG: syslog.syslog(logtype + "no more users allowed for group '" + str(L.split(":")[0]) + "'")
            allow.append(False)

          else:
            if DEBUG: syslog.syslog(logtype + "free place for group " +str(L.split(":")[0]))
            allow.append(True)
        except:
          if DEBUG: syslog.syslog(logtype + "wrong defined rule NUMBER '" + str(L) + "'. This value should be an integer... skipping")
      else:
        if DEBUG: syslog.syslog(logtype + "user '" + str(login) + "' is not in group '" + L.split(":")[0] + "'")

  if len(allow) == 0:
    if DEBUG: syslog.syslog(logtype + "all NUMBER rules have nothing to do with user '" + str(login) + "'")
    return True

  if any(allow): return True
  else:          return False


def get_users_from_group(group):
  try:
    out = sp.Popen(["/usr/bin/getent", "group", group], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0].split("\n")[0]
    out = out.split(":")[-1]
    return out.split(",")
  except:
    syslog.syslog(logtype + "I got nothing from getent...")
    sys.exit(2)


def dialog(rhost, user):
  """
  This calls UserInterface to get confirmations about creating new session.
  It also notified user about session termination.
  At the moment it uses for SSH confirmations only (config file rule 'GUI').
  """
  return sp.Popen(["/usr/share/pamac/kdialog-ssh.py", str(rhost), str(user), "ask"], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0]


def check(logtype, access, i, rules, login, DEBUG):
  """
  It get list of rules, parses these and fills 'access' dictonary with 4
  lists: CLOSE, GUI, OPEN and NUMBER.
  """
  for r in rules:
    if DEBUG: syslog.syslog(logtype + "rules: "+ str(r))
    if i['OPTION'].split(" ")[0] == r: #OPEN, GUI, CLOSE, NUMBER
      if DEBUG: syslog.syslog(logtype + "that was interpreted as " + r +": "+ str(i['OPTION'].split(" ")[0]))

      if i['OPTION'].split(" ")[1] == "USER":
        if DEBUG: syslog.syslog(logtype + "I'm going to look at USERS list: " +str(i['OPTION'].split(" ")[1]))
        access[r] = access[r] + i['LIST']
 
      elif i['OPTION'].split(" ")[1] == "GROUP":
        if i['OPTION'].split(" ")[0] == "NUMBER":
          if DEBUG: syslog.syslog(logtype + "I'm going to look at NUMBER of USERS in GROUP: " +str(i['OPTION'].split(" ")[1]))
          access[r] = access[r] + i['LIST']
        else:
          if DEBUG: syslog.syslog(logtype + "I'm going to look at GROUP list: " +str(i['OPTION'].split(" ")[1]))
          for group in i['LIST']:
            access[r] = access[r] + get_users_from_group(group)
  return access


def allow(SERVICE, logtype, host, login):
  access = {"OPEN":[], "GUI":[], "CLOSE":[], "NUMBER":[]}
  ret = None
  DEFAULT, DEBUG = get_default(logtype)

  for rule in config_parser(logtype, SERVICE, DEBUG):
    if DEBUG:
      syslog.syslog(logtype + "----------------------------------------------")
      syslog.syslog(logtype + "rule = " +str(rule))
    access.update(check(logtype, access, rule, ["OPEN", "GUI", "CLOSE", "NUMBER"], login, DEBUG))

  if DEBUG:
    syslog.syslog("OPEN for  : "+str(access['OPEN']))
    syslog.syslog("CLOSE for : "+str(access['CLOSE']))
    syslog.syslog("GUI for   : "+str(access['GUI']))
    syslog.syslog("NUMBER for: "+str(access['NUMBER']))

  if len(access['NUMBER']) > 0:
    if not check_number_in_group(logtype, login, access['NUMBER'], DEBUG):
      if DEBUG: syslog.syslog(logtype + "'allow()' returns 'CLOSE', because of access[NUMBER]")
      return "CLOSE"

  for i in access['OPEN']:
    if i in access['CLOSE']: access['OPEN'].remove(i)

  if login in access['CLOSE']:  return "CLOSE"
  elif login in access['GUI']:
    if SERVICE == "SSH":        return "GUI"
    else:                       return "CLOSE"
  elif login in access['OPEN']: return "OPEN"
  else:                         return DEFAULT


def main(SERVICE, logtype, pamh, flags, argv):
  """
  Start point for creating new sessions. It asks function 'allow'
  to define next steps. Function 'main' uses PAM object 'pamh' and
  its methods to define name of the remote host and user's name.
  """
  pamh.authtok
  try:
    user = pamh.get_user()
    syslog.syslog(logtype + "remote user: "+ str(user))
    rhost = pamh.rhost
    syslog.syslog(logtype + "remote host: "+ str(rhost))

  except pamh.exception, e:
    syslog.syslog(logtype + "something goes wrong... no info about remote connection")
    return e.pam_result

  mode = allow(SERVICE, logtype, rhost, user)
  syslog.syslog(logtype + "main got from allow: "+str(mode))

  if mode == "GUI":
    ret = str(dialog(rhost, user))
    #syslog.syslog(logtype + "kdialog returns = " + ret)
    try:
      if int(ret) == 0:
        create_log(logtype, SERVICE, rhost, user, mode, "creating new session")
        return pamh.PAM_SUCCESS
      else:
        return pamh.PAM_AUTH_ERR
    except:
      syslog.syslog(logtype + "something goes wrong... no return value from kdialog")
      return pamh.PAM_AUTH_ERR

  elif mode == "CLOSE":
    create_log(logtype, SERVICE, rhost, user, mode, "access denied")
    syslog.syslog(logtype + "access denied")
    return pamh.PAM_AUTH_ERR

  elif mode == "OPEN":
    create_log(logtype, SERVICE, rhost, user, mode, "access granted")
    syslog.syslog(logtype + "access granted")
    return pamh.PAM_SUCCESS

  else:
    syslog.syslog(logtype + "I don't know what to do now... " +str(mode))
    return pamh.PAM_AUTH_ERR


def pam_sm_authenticate(pamh, flags, argv):
  logtype = "pamac(" + str(pamh.service) + "): "
  syslog.syslog(logtype + "authenticate")
  pamh.authtok
  try:
    syslog.syslog(logtype + "remote user: "+ str(pamh.get_user()))
    syslog.syslog(logtype + "remote host: "+ str(pamh.rhost))
  except pamh.exception, e:
    syslog.syslog(logtype + "something goes wrong... no info about remote connection")
    return pamh.PAM_AUTH_ERR

  if str(pamh.service) == "kdm":
    return main("KDM", logtype, pamh, flags, argv)

  return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh, flags, argv):
  logtype = "pamac(" + str(pamh.service) + "): "
  syslog.syslog(logtype + "close session")

  if not check_log(logtype, "SSH", str(pamh.rhost), str(pamh.get_user())):
    syslog.syslog(logtype + "no need to notify")
  else:
    sp.Popen(["/usr/share/pamac/kdialog-ssh.py", str(pamh.rhost), str(pamh.get_user()), "info"], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)

  return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):
  logtype = "pamac(" + str(pamh.service) + "): "

  if str(pamh.service) == "sshd":
    SERVICE = "SSH"
  elif str(pamh.service) == "kdm":
    # We check KDM's rules on the 'auth' step.
    # (because we want to show error message (in CLOSE case)
    # and it's possible only BEFORE KDE-session starts)
    return pamh.PAM_SUCCESS
  elif str(pamh.service) == "login":
    SERVICE = "TTY"
  else:
    syslog.syslog(logtype + "can't define PAM service...")
    sys.exit(2)

  syslog.syslog(logtype + "open session")
  return main(SERVICE, logtype, pamh, flags, argv)

def pam_sm_setcred(pamh, flags, argv):
  return pamh.PAM_SUCCESS
