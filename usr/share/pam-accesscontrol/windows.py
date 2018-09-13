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

class INFO(QtWidgets.QWidget):
  def __init__(self, USER, HOST, SERVICE):
    super(INFO, self).__init__()

    AUTH = None
    if SERVICE == "sshd-key": AUTH = "SSH public-key authentication"
    elif SERVICE == "sshd":   AUTH = "SSH password authentication"

    if SERVICE in ['sshd','sshd-key']: SERVICE = "SSH"
    if AUTH:
      reply = QtWidgets.QMessageBox.information(self, SERVICE + ': connection closed',
            "Connection closed by remote host.\n\nUser: " + USER + "\nHost: " + HOST +
            "\n\nAuthentication: " + AUTH)
    else:
      reply = QtWidgets.QMessageBox.information(self, SERVICE + ': connection closed',
            "Connection closed by remote host.\n\nUser: " + USER + "\nHost: " + HOST)


class ASK(QtWidgets.QWidget):
  def __init__(self, USER, HOST, SERVICE):
    super(ASK, self).__init__()

    AUTH = None
    if SERVICE == "sshd-key": AUTH = "SSH public-key authentication"
    elif SERVICE == "sshd":   AUTH = "SSH password authentication"

    if SERVICE in ['sshd','sshd-key']: SERVICE = "SSH"

    if AUTH:
      reply = QtWidgets.QMessageBox.question(self, 'New ' + SERVICE + ' connection',
            "New incoming " + SERVICE + " connection has been established.\nDo you want to allow it?\n\nUser: "
            + USER + "\nHost: " + HOST + "\n\nAuthentication: "+ AUTH,
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)
    else:
      reply = QtWidgets.QMessageBox.question(self, 'New ' + SERVICE + ' connection',
            "New incoming " + SERVICE + " connection has been established.\nDo you want to allow it?\n\nUser: "
            + USER + "\nHost: " + HOST,
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No)

    if reply == QtWidgets.QMessageBox.Yes:
      sys.exit(0)
    else:
      sys.exit(1)


class ACCESS_DENIED(QtWidgets.QWidget):
  def __init__(self, USER):
    super(ACCESS_DENIED, self).__init__()
    reply = QtWidgets.QMessageBox.information(self, 'ACCESS DENIED',
            "Login not possible for user '" + USER + "'.\nACCESS DENIED.")



if __name__ == '__main__':
  if (len(sys.argv) != 5) or sys.argv[1] not in ["ask","info","xorg"]:
    print ("usage: " + sys.argv[0] + " [ask | info | xorg] HOST USER PAM-SERVICE")
    sys.exit(1)

  if sys.argv[2] == "::1":
    HOST = "localhost"
  else:
    HOST = sys.argv[2]

  USER    = sys.argv[3]
  SERVICE = sys.argv[4]

  app = QtWidgets.QApplication(sys.argv)

  if   sys.argv[1] == "ask":    ASK(USER, HOST, SERVICE)
  elif sys.argv[1] == "info":   INFO(USER, HOST, SERVICE)
  elif sys.argv[1] == "xorg":   ACCESS_DENIED(USER)
