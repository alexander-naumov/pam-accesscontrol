---
layout: default
---
## Description

PAM-accesscontrol is the highly intellectual and easily configurable system to control
access to host via PAM interfaces. It makes it possible to manages access for user,
group of users or LDAP-groups (supports FreeIPA and Active Directory) by adding just one
line to the config file. It makes it possible to be notifyed about establisching each new
incoming connection and allow or not allow it (by using notification window). It's also
possible get notification via email about opening/closing every new SSH session.

PAM-accesscontrol supports and recognizes SSH password and public key authentication and
uses Syslog for every login-events. This is the last security layer for enterprises and
personal use.

## Workflow

```
                 | ->> PyQt5_confirmation [allow or not]
                 |                                              +-+-+-+
                 |      | ->> notification_mails                +     +  <-- kdm
               __|______|_________        _______________       +     +  <-- ftp
  Config ->>  |                   |      |               |      +     +  <-- sshd
              | PAM-accesscontrol | <==> | pam_python.so | <==> + PAM +  <-- login
  Syslog <<-  |                   |      |               |      +     +  <-- sddm
 Logfile <<-  |___________________|      |_______________|      +     +  <-- lightdm
                 |                                              +     +  <-- ...
                 |                                              +-+-+-+
                 | <<- Loginctl(1) <<- SessionInfo


```
