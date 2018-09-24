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
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *

class win(QWidget):
  def __init__(self, USER, HOST, SERVICE):
    super(win, self).__init__()

    self.AUTH = None
    if SERVICE == "sshd-key": self.AUTH = "SSH public-key authentication"
    elif SERVICE == "sshd":   self.AUTH = "SSH password authentication"

    if SERVICE in ['sshd','sshd-key']:
      self.SERVICE = "SSH"
    else:
      self.SERVICE = SERVICE

    self.w = QMessageBox()
    self.w.setIconPixmap(QPixmap('/usr/share/pam-accesscontrol/img/lock.gif'))
    icon_label = self.w.findChild(QLabel,"qt_msgboxex_icon_label")
    movie = QMovie('/usr/share/pam-accesscontrol/img/lock.gif')
    setattr(self.w,'icon_label',movie)
    icon_label.setMovie(movie)
    movie.start()


  def close(self):
    self.TEXT = "Connection closed by remote host.\n\nUser: " + USER + "\nHost: " + HOST
    if self.AUTH:
      self.TEXT = self.TEXT + "\n\nAuthentication: "+ self.AUTH

    self.w.setWindowTitle(self.tr(self.SERVICE + ': connection closed'))
    self.w.setText(self.TEXT)
    self.w.exec_()


  def ask(self):
    self.TEXT = "New incoming " + self.SERVICE + " connection has been established. " + \
                "Do you want to allow it?\n\nUser: " + USER + "\nHost: " + HOST
    if self.AUTH:
      self.TEXT = self.TEXT + "\n\nAuthentication: "+ self.AUTH

    self.w.setWindowTitle(self.tr('New ' + self.SERVICE + ' connection'))
    self.w.setText(self.TEXT)
    self.w.setStandardButtons(QMessageBox.Yes  | QMessageBox.No)
    self.w.setDefaultButton(QMessageBox.No)

    if self.w.exec_() == QMessageBox.Yes:
      sys.exit(0)
    else:
      sys.exit(1)


  def xorg(self):
    self.w.setGeometry(100, 50, 100, 100)

    self.TEXT = "ACCESS DENIED\n\n\nLogin not possible for user '" + USER + "'"
    self.w.setWindowTitle(self.tr('ACCESS DENIED'))
    self.w.setText(self.TEXT)
    self.w.exec_()


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

  app = QApplication(sys.argv)

  if   sys.argv[1] == "ask":    win(USER, HOST, SERVICE).ask()
  elif sys.argv[1] == "info":   win(USER, HOST, SERVICE).close()
  elif sys.argv[1] == "xorg":   win(USER, HOST, SERVICE).xorg()
