=========================================
 pam-accesscontrol
=========================================
PAM-ACCESSCONTROL is a pam-module writen in python3 for control access to host via SSH,
sddm, slim, kdm, lightdm, xdm and tty/login(1). It makes it possible to manages access
for some user or, for example, LDAP-groups of users by adding just one line to the config
file. It's also possbile to get notification about establisching each new incoming
SSH connection and allow or not allow it (by using PyQt5 notification window).
It recognizes SSH password and public key authentication.

.. image:: https://de.opensuse.org/images/7/77/Paket-Download-Icon.png
   :target: https://software.opensuse.org//download.html?project=home%3AAlexander_Naumov%3Apam-accesscontrol&package=pam-accesscontrol

We provide packages for many different GNU/Linux systems to make it easy to install or update pam-accesscontrol.

Contributing
------------
You can submit or ask for improvements using github's Pull Requests or Issues.

If you're going to send me a patch, please make sure that `OBS`_ is still be able to build packages.

Credits
-------

Copyright (c) 2017-2018 Alexander Naumov (alexander_naumov@opensuse.org).

Licensed under GNU GPLv3 (see docs/LICENSE file).

.. _OBS: https://build.opensuse.org/package/show/home:Alexander_Naumov:pam-accesscontrol/pam-accesscontrol
