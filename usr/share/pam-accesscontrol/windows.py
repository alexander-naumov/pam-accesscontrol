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


import syslog, os, sys
from PyQt5 import QtGui, QtWidgets

class SSH_INFO(QtWidgets.QWidget):
  def __init__(self, USER, HOST, AUTH):
    super(SSH_INFO, self).__init__()
    reply = QtWidgets.QMessageBox.information(self, 'SSH disconnection',
            "SSH connection has been ended.\n\nUser: " + USER + "\nHost: " + HOST)

class SSH_ASK(QtWidgets.QWidget):
  def __init__(self, USER, HOST, AUTH):
    super(SSH_ASK, self).__init__()
    if AUTH == "sshd-key": AUTH = "public-key authentication"
    else:                  AUTH = "password authentication"

    reply = QtWidgets.QMessageBox.question(self, 'New SSH connection',
            "New incoming SSH connection has been established.\nDo you want to allow it?\n\nUser: "
            + USER + "\nHost: " + HOST + "\n\nAuthentication: "+ AUTH,
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)

    if reply == QtWidgets.QMessageBox.Yes:
      sys.exit(0)
    else:
      sys.exit(1)

class ACCESS_DENIED(QtWidgets.QWidget):
  def __init__(self, USER):
    super(ACCESS_DENIED, self).__init__()
    reply = QtWidgets.QMessageBox.information(self, 'ACCESS DENIED',
            "Login is not possible for user '" + str(USER) + "'.\nACCESS DENIED.")



if __name__ == '__main__':
  if (len(sys.argv) != 5) or sys.argv[1] not in ["ask","info","xorg"]:
    print ("usage: " + sys.argv[0] + " [ask | info | xorg] HOST USER [sshd | sshd-key | XDM]")
    sys.exit(1)

  if sys.argv[2] == "::1":
    HOST = "localhost"
  else:
    HOST = sys.argv[2]

  app = QtWidgets.QApplication(sys.argv)

  if   sys.argv[1] == "ask":    SSH_ASK(str(sys.argv[3]), str(HOST), str(sys.argv[4]))
  elif sys.argv[1] == "info":   SSH_INFO(str(sys.argv[3]), str(HOST), str(sys.argv[4]))
  elif sys.argv[1] == "xorg":   ACCESS_DENIED(str(sys.argv[3]))
