#!/usr/bin/python3 -Es
# -*- coding: utf-8 -*-

# This file is part of pam-accesscontrol.
#
#    Copyright (C) 2017  Alexander Naumov <alexander_naumov@opensuse.org>
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
import tkinter
from tkinter import messagebox

if __name__ == '__main__':
  if (len(sys.argv) != 4) or sys.argv[1] not in ["ssh-ask","ssh-info","access-denied-xorg"]:
    print ("usage: " + sys.argv[0] + " [ssh-ask | ssh-info | access-denied-xorg] HOST USER")
    sys.exit(1)

  root = tkinter.Tk()
  root.withdraw()

  ret = 'yes'

  if sys.argv[1] == "ssh-ask":
    ret = messagebox.askquestion("New SSH connection",
            "New incoming SSH connection has been established.\nDo you want to allow it?\n\nUser: "
            + str(sys.argv[3]) + "\nHost: " + str(sys.argv[2]), icon='warning')

  elif sys.argv[1] == "ssh-info":
    ret = messagebox.showinfo("SSH disconection",
            "SSH connection has been ended.\n\nHost: " + str(sys.argv[3]) + "\nUser: " + str(sys.argv[2]))

  elif sys.argv[1] == "access-denied-xorg":
    ret = messagebox.showinfo("", "ACCESS DENIED.\nLogin not possible.", icon='warning')

  if ret == 'yes': sys.exit(0)
  else: sys.exit(1)
