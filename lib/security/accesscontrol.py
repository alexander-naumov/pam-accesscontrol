# This file is part of pam-accesscontrol.
#
#    Copyright (C) 2017-2019  Alexander Naumov <alexander_naumov@opensuse.org>
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

import subprocess as sp
import syslog, os, re, datetime, grp, pwd

from ctypes import *
from ctypes.util import find_library

log_prefix = ""


def log(log_message):
  syslog.syslog(log_prefix + str(log_message))


def create_log(SERVICE, rhost, user, mode, msg):
  """
  It creates new entry in the logfile. The format of log-entry is:
  date <SPACE> current time <TAB> service name <TAB> rule <TAB> username@hostname <TAB> some_text <newline>
  """
  now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  FILE = '/var/log/pam-accesscontrol-' + str(datetime.datetime.now().strftime("%Y-%m")) + '.log'

  if not rhost: rhost = "localhost"
  try:
    fd = open(FILE, 'a+')
    fd.write("%s%s%s%s%s\n" % (now.ljust(23), SERVICE.ljust(10), str(mode).ljust(10), (str(user) + "@" + str(rhost)).ljust(50), msg.ljust(15)))
    fd.close()
  except:
    log("can't open/write logfile " + FILE)


def check_log(SERVICE, rhost, user):
  """
  This funtion can be used to figure out is the current SSH session last on or not.
  In fact we have mulisessions (sessions inside other sessions), but we should be
  notified only about last one.
  """
  FILE = '/var/log/pam-accesscontrol-' + str(datetime.datetime.now().strftime("%Y-%m")) + '.log'

  try:
    fd = open(FILE, 'a+')
    logfile = reversed(fd.read().split("\n"))
    fd.close()
  except:
    log("can't open/read logfile " + FILE)
    return 0

  for l in logfile:
    if len(l) > 0:
      L = [L for L in l.split(" ") if len(L)>0 and re.search('[a-zA-Z]', L)]
      if L[2] == str(user + "@" + rhost):
        if L[4] in ["new", "granted"]:
          #log("closing session - user:" + str(user) + " host:"+str(rhost))
          create_log(SERVICE, rhost, user, L[1], "closing session")
          if L[1] == "ASK":
            return 1
          else:
            return 0
  return 0


def ids(LIST):
  return [L for L in LIST.split(",") if len(L)>0]


def not_upper_last_element(config):
  """
  Last rule's element is a username. We won't 'upper' it. Rest should be
  'upper'ed to fix difference between capital and lowercase letters
  (to be able to use both in the config file).
  We also should be carefull with unnecessary spaces that generates excess
  rule's options.
  """
  conf = []
  for line in config:
    if len(line.split(" "))>1:
      line = " ".join([x for x in line.split(" ") if len(x) > 0])
      line = " ".join([x for x in line.upper().split(" ")[:-1]]) + " " + line.split(" ")[-1]
    conf.append(line)
  return conf


def configuration(PATH):
  """
  Reading configuration from the config file.
  """
  all_conf = []
  try:
    with open("/etc/pam-accesscontrol.d/" + PATH, 'r') as fd:
      conf = fd.read().split("\n")
      conf = not_upper_last_element(conf)
      all_conf = all_conf + conf
  except:
    log("can't open/read file: " + PATH)
  #log("config: " + str(all_conf))
  return all_conf


def get_default():
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

  for line in configuration("pam-accesscontrol.conf"):
    line = line.upper()
    if line[:8] == "DEFAULT:":
      if line.split(":")[1] in ['CLOSE', 'OPEN']:
        #log("default access rule: " + line.split(":")[1])
        DEFAULT = line.split(":")[1]
      else:
        log("default: CLOSE")

    if line[:6] == "DEBUG:":
      DEBUG = line.split(":")[1]
      if DEBUG.lower() == 'true': DEBUG = True
      else:                       DEBUG = False

  if DEBUG: log("default access rule: " + DEFAULT)
  return DEFAULT, DEBUG


def config_parser(SERVICE, DEBUG):
  """
  It reads and parses the config file and returns the LIST of the correctly
  defined rules. Broken rules will be just ignored (for security reason).
  """
  rules = []
  for rule in [c for c in configuration("pam-accesscontrol.conf") if len(c) > 5]:
    if DEBUG: log("rule: " + str(rule))
    dic = {}
    if rule[0] == '#':
      pass

    elif re.search(':', rule):
      if rule.split(':')[0].upper() not in ['MAILSERVER', 'DEBUG', 'DEFAULT']:
        if DEBUG: log("Wrong option, ignoring: " + str(rule))

    elif len(rule.split(" ")) != 4:
      if DEBUG: log("broken rule, wrong number of options... skipping: " +str(rule))

    elif rule.split(" ")[0] != SERVICE.upper():
      if DEBUG: log("other service... skipping: " + str(rule))

    elif rule.split(" ")[1] not in ['OPEN', 'CLOSE', 'ASK','NUMBER', 'PIN']:
      if DEBUG: log("second parameter is broken: " +str(rule))

    elif rule.split(" ")[2] not in ['USER', 'GROUP']:
      if DEBUG: log("third parameter is broken: " +str(rule))

    else:
      dic['OPTION'] = str(rule.split(" ")[1] + " " + rule.split(" ")[2])
      dic['LIST'] = ids(rule.split(" ")[3])
      rules.append(dic)
  return rules


def number_of_logged_already(login, group, DEBUG):
  """
  Use this function to figure out number of already logged users which
  belong to the 'group'. Users with the same login (name) are not counted,
  i.e. one user can create n sessions and in this case we still have ONE user.
  It takes 'login' as a parameter to be able to calculate number of users
  after creating this new session.
  """
  item = 0
  USERS = []
  users_in_system = sp.Popen(["/bin/loginctl", "list-users"],stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0].split("\n")
  for users in users_in_system[1:-3]:
    USERS.append([user for user in users.split(" ") if len(user)>0][-1])

  if DEBUG: log("USERS list: " + str(USERS))
  USERS.append(login)
  USERS = dict(zip(USERS, USERS)).values() #delete same users: bob,tom,tom,tom => bob,tom
  if DEBUG: log("USERS list after compression: " + str(USERS))

  for U in USERS:
    if U in check_users_group_list(group, login, DEBUG):
      item = item+1
  if DEBUG: log("number of users (group '" + str(group) + "') after new connection: " + str(item))
  return item


def check_number_in_group(login, LIST, DEBUG):
  """
  It checks LIST of NUMBER rule to make a decision about creating new session.
  """
  allow = []
  for L in LIST:
    if len(L.split(":")) != 2:
      if DEBUG: log("wrong defined rule NUMBER '" + str(L) + "'... skipping")
    else:
      if login in check_users_group_list(L.split(":")[0], login, DEBUG):
        try:
          if int(L.split(":")[1]) < int(number_of_logged_already(login, L.split(":")[0], DEBUG)):
            if DEBUG: log("no more users allowed for group '" + str(L.split(":")[0]) + "'")
            allow.append(False)

          else:
            if DEBUG: log("free place for group " +str(L.split(":")[0]))
            allow.append(True)
        except:
          if DEBUG: log("wrong defined rule NUMBER '" + str(L) + "'. This value should be an integer... skipping")
      else:
        if DEBUG: log("user '" + str(login) + "' is not in group '" + L.split(":")[0] + "'")

  if len(allow) == 0:
    if DEBUG: log("all NUMBER rules have nothing to do with user '" + str(login) + "'")
    return True

  if any(allow): return True
  else:          return False


def check_users_group_list(group, login, DEBUG):
  """
  This function tries to call glibc to get the list of user's groups.
  Theoretically, it should support local host groups, LDAP groups and sssd+LDAP (freeIPA, AD).
  Type of the return value should be a LIST; empty LIST is authorized.
  """
  if group == "ALL":
    if DEBUG: log("okay, group 'ALL' means everyone")
    return [str(login)]

  getgrouplist = cdll.LoadLibrary(find_library('libc')).getgrouplist

  ngroups = 30
  getgrouplist.argtypes = [c_char_p, c_uint, POINTER(c_uint * ngroups), POINTER(c_int)]
  getgrouplist.restype = c_int32

  grouplist = (c_uint * ngroups)()
  ngrouplist = c_int(ngroups)

  user = pwd.getpwnam(login)
  ct = getgrouplist(user.pw_name, user.pw_gid, byref(grouplist), byref(ngrouplist))

  # if 30 groups was not enought this will be -1, try again
  # luckily the last call put the correct number of groups in ngrouplist
  if ct < 0:
    getgrouplist.argtypes = [c_char_p, c_uint, POINTER(c_uint *int(ngrouplist.value)), POINTER(c_int)]
    grouplist = (c_uint * int(ngrouplist.value))()
    ct = getgrouplist(user.pw_name, user.pw_gid, byref(grouplist), byref(ngrouplist))

  for i in xrange(0, ct):
    gid = grouplist[i]
    if (group == grp.getgrgid(gid).gr_name):
      if DEBUG: log("user '" + str(login) + "' is a member of group '" + str(group) + "'")
      return [str(login)]
  return []


def dialog(DEBUG, rhost, user, flavor, SERVICE):
  """
  This calls UserInterface to get confirmations about creating new session.
  It also notified user about session termination.
  """
  return sp.Popen(["/usr/share/pam-accesscontrol/notifications.py",
      str(DEBUG), str(rhost), str(user), flavor, SERVICE], stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE).communicate()[0]


def check(access, i, rules, login, DEBUG):
  """
  It gets list of rules, parses it and fills the 'access' dictonary with 4
  lists: CLOSE, ASK, OPEN and NUMBER.
  """
  for r in rules:
    if DEBUG: log("rules: "+ str(r))
    if i['OPTION'].split(" ")[0] == r: #OPEN, ASK, CLOSE, NUMBER, PIN
      if DEBUG: log("that was interpreted as " + r +": "+ str(i['OPTION'].split(" ")[0]))

      if i['OPTION'].split(" ")[1] == "USER":
        if DEBUG: log("I'm going to look at USERS list: " +str(i['OPTION'].split(" ")[1]))
        access[r] = access[r] + i['LIST']
 
      elif i['OPTION'].split(" ")[1] == "GROUP":
        if i['OPTION'].split(" ")[0] == "NUMBER":
          if DEBUG: log("I'm going to look at NUMBER of USERS in GROUP: " +str(i['OPTION'].split(" ")[1]))
          access[r] = access[r] + i['LIST']
        else:
          if DEBUG: log("I'm going to look at GROUP list: " +str(i['OPTION'].split(" ")[1]))
          for group in i['LIST']:
            access[r] = access[r] + check_users_group_list(group, login, DEBUG)
  return access


def allow(SERVICE, login, DEFAULT, DEBUG):
  access = {"OPEN":[], "ASK":[], "CLOSE":[], "NUMBER":[], "PIN":[]}
  ret = None

  for rule in config_parser(SERVICE, DEBUG):
    if DEBUG:
      log("----------------------------------------------")
      log("rule = " +str(rule))
    access.update(check(access, rule, ["OPEN", "ASK", "CLOSE", "NUMBER", "PIN"], login, DEBUG))

  if DEBUG:
    log("----------------------------------------------")
    log("OPEN for  : "+str(access['OPEN']))
    log("CLOSE for : "+str(access['CLOSE']))
    log("ASK for   : "+str(access['ASK']))
    log("NUMBER for: "+str(access['NUMBER']))
    log("PIN for   : "+str(access['PIN']))

  if len(access['NUMBER']) > 0:
    if not check_number_in_group(login, access['NUMBER'], DEBUG):
      if DEBUG: log("'allow()' returns 'CLOSE', because of access[NUMBER]")
      return "CLOSE"

  # Priority of CLOSE rule is higher than OPEN
  for i in access['OPEN']:
    if i in access['CLOSE']: access['OPEN'].remove(i)

  if login in access['CLOSE']:          return "CLOSE"
  elif login in access['PIN']:          return "PIN"
  elif login in access['ASK']:
    if SERVICE in ["sshd", "sshd-key"]: return "ASK"
    else:                               return "CLOSE"
  elif login in access['OPEN']:         return "OPEN"
  else:                                 return DEFAULT


def generate_pin():
  import random, string
  return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))


def send_mail(pamh, type_of_mail, pin=None):
  """
  The idea is to find mail_server's IP and recipient address in the config file
  and send mail. There are 3 types of mails: 1) notification for creating new session,
  2) notification for closing opened session and 3) sending one time PIN
  (two-factor-authentication).

  Input: pamh object
  Output: VOID
  """
  ADDR = []
  subj_prefix = ""

  if type_of_mail[:6] == 'notify':
    if not os.path.exists("/etc/pam-accesscontrol.d/mail-notification.conf"):
      return
    if type_of_mail[7:10] == 'new':
      subj_prefix = " (creating new session)"
    elif type_of_mail[7:12] == 'close':
      subj_prefix = " (closing session)"

    for rule in configuration("mail-notification.conf"):
      if rule.split(" ")[0] == str(pamh.service).upper():
        ADDR = ADDR + ids(rule.split(" ")[1])
        ADDR = dict(zip(ADDR, ADDR)).values()

  elif type_of_mail == 'pin':
    if not os.path.exists("/etc/pam-accesscontrol.d/login-mail-mapping.conf"):
      log("Can't send PIN, no login-mail-mapping found...")
      return pamh.PAM_AUTH_ERR

    subj_prefix = " (one time PIN)"
    for rule in configuration("login-mail-mapping.conf"):
      #log("rule.split(" ")[0] = " + str(rule.split(" ")[0]))
      #log(str(pamh.get_user()).upper())
      if rule.split(" ")[0] == str(pamh.get_user()).upper():
        #log("PIN rule = " + str(rule))
        ADDR = ADDR + ids(rule.split(" ")[1])
        ADDR = dict(zip(ADDR, ADDR)).values()

  import smtplib, socket
  server = None
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("8.8.8.8", 80))
  MY_IP = s.getsockname()[0]
  s.close()

  for rule in configuration("pam-accesscontrol.conf"):
    if rule[0:11] == "MAILSERVER:":
      server = rule[11:]
      log("MAIL SERVER: " + str(server))

  if not server:
    log("can't send mail... MTA IP is not found.")
    return

  subject  = "[PAM-ACCESSCONTROL] " + MY_IP + " : " + pamh.service + subj_prefix
  fromaddr = 'pam-accesscontrol@localhost'

  if ADDR:
    toaddr = ", ".join(ADDR)
    if len(toaddr)<7:
      log("can't send mail... bad recipient mail address.")
      return
    else:
      msg = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n" % (fromaddr, toaddr, subject))
  else:
    log("can't send mail... no recipient mail address found.")
    return

  if type_of_mail == 'pin':
    msg = (msg + "*** Security notification ***\n" +
            "\nPIN for this session: " + str(pin))

  elif type_of_mail == 'notify_new_session':
    msg = (msg + "*** Security notification ***\n" +
                 "\nSource:  " + str(pamh.rhost) +
                 "\nTarget:  " + MY_IP +
                 "\nService: " + pamh.service +
                 "\nUser:    " + str(pamh.get_user()) +
                 "\n\nSuccessfully logged in")

  elif type_of_mail == 'notify_close_session':
    msg = (msg + "*** Security notification ***\n" +
            "\nSession for user '" + str(pamh.get_user()) +
            "' is closed")

  try:
    server = smtplib.SMTP(server)
    #server.set_debuglevel(1)
    server.sendmail(fromaddr, toaddr, msg)
    server.quit()
    log("send notification mail to: " + toaddr)
  except Exception:
    log("can't send mail... MTA error: " + str(Exception))



def main(SERVICE, pamh, flags, argv):
  """
  Start point for creating new sessions. It asks function 'allow'
  to define next steps. Function 'main' uses PAM object 'pamh' and
  its methods to define name of the remote host and user's name.
  """
  DEFAULT, DEBUG = get_default()
  try:
    user = pamh.get_user()
    rhost = pamh.rhost
  except pamh.exception:
    log("something goes wrong... no info about remote connection")
    return pamh.exception.pam_result

  mode = allow(SERVICE, user, DEFAULT, DEBUG)
  if DEBUG: log("main got from allow: "+str(mode))

  if mode == "PIN":
    if flags == 0:
      return pamh.PAM_SUCCESS
    
    pin = generate_pin()
    if DEBUG: log("Generated PIN: " + str(pin))

    send_mail(pamh, 'pin', pin)
    resp = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "PIN: "))
    if DEBUG: log("Entered PIN: " + str(i.resp))

    if str(resp.resp) == str(pin):
      return pamh.PAM_SUCCESS
    else:
      return pamh.PAM_AUTH_ERR

  elif mode == "ASK":
    if DEBUG: log("SHOW ME WINDOW")
    ret = str(dialog(DEBUG, rhost, user, "ask", SERVICE))
    if DEBUG: log("[0->Yes; 1->No] RET = " + str(ret))
    try:
      if int(ret) == 0:
        if allow(SERVICE, user, DEFAULT, False) == "ASK":
          if flags == 0: create_log(SERVICE, rhost, user, mode, "creating new session")
          log("access granted")
          return pamh.PAM_SUCCESS
        else:
          log("connection CAN NOT be established; because of NUMBER rule")
          return pamh.PAM_AUTH_ERR
      else:
        log("connection SHOULD NOT be established; because of X-session owner's decision")
        return pamh.PAM_AUTH_ERR
    except:
      log("something goes wrong... no return value from notification window")
      return pamh.PAM_AUTH_ERR

  elif mode == "CLOSE":
    if flags == 0: create_log(SERVICE, rhost, user, mode, "access denied")
    log("access denied")
    if str(pamh.service) in ["slim","sddm","lightdm","xdm","kdm"]:
      dialog(DEBUG, rhost, user, "xorg", SERVICE)
    return pamh.PAM_AUTH_ERR

  elif mode == "OPEN":
    if flags == 0: create_log( SERVICE, rhost, user, mode, "access granted")
    log("access granted")
    return pamh.PAM_SUCCESS

  else:
    log("I don't know what to do now... " +str(mode))
    return pamh.PAM_AUTH_ERR


def pam_sm_authenticate(pamh, flags, argv):
  global log_prefix
  log_prefix = "pam-accesscontrol(" + str(pamh.service) + ":" + str(pamh.get_user()) +"): "

  log("==============================================")
  log("authentication")

  try:
    log("remote user: "+ str(pamh.get_user()))
    log("remote host: "+ str(pamh.rhost))
  except pamh.exception:
    log("something goes wrong... no info about remote connection")
    return pamh.PAM_AUTH_ERR

  if str(pamh.service) == "sshd":
    try:
      os.mknod("/tmp/session-" + str(pamh.pamh))
    except:
      log("can't create new file in /tmp...")

  return main(str(pamh.service), pamh, flags, argv)


def pam_sm_close_session(pamh, flags, argv):
  global log_prefix
  log_prefix = "pam-accesscontrol(" + str(pamh.service) + ":" + str(pamh.get_user()) +"): "
  log("closing session")

  DEFAULT, DEBUG = get_default()
  if not check_log("sshd", str(pamh.rhost), str(pamh.get_user())):
    log("no need to GUI notify")
  else:
    if DEBUG: log("SHOW ME WINDOW")
    dialog(DEBUG, str(pamh.rhost), str(pamh.get_user()), "info", str(pamh.service))

  send_mail(pamh, 'notify_close_session')
  log("==============================================")
  return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):
  global log_prefix
  log_prefix = "pam-accesscontrol(" + str(pamh.service) + ":" + str(pamh.get_user()) +"): "

  log("==============================================")
  log("open new session")

  if str(pamh.service) == "sshd":
    if os.path.isfile("/tmp/session-" + str(pamh.pamh)):
      SERVICE = "sshd"
      os.remove("/tmp/session-" + str(pamh.pamh))
    else:
      SERVICE = "sshd-key"
    log(SERVICE)
    state = main(SERVICE, pamh, flags, argv)

  elif str(pamh.service) in ["slim","sddm","lightdm","xdm","kdm"]:
    # We check XDM's rules on the 'auth' step.
    # (because we want to show error message (in CLOSE case)
    # and it's possible only BEFORE KDE-session starts)
    state = 0

  else:
    state = main(str(pamh.service), pamh, flags, argv)

  if state == 0: send_mail(pamh, 'notify_new_session')
  log("==============================================")
  return state

def pam_sm_setcred(pamh, flags, argv):
  return pamh.PAM_SUCCESS
