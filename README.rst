=========================================
 pam-accesscontrol
=========================================
PAM-ACCESSCONTROL is writen in python and use PAM to control access to the system via SSH,
sddm, slim, kdm, lightdm, xdm and tty/login(1). It makes it possible to manages access
for some group of users or, for example, depend on configuration can ask you (by using PyQt
notification window) for each new incoming SSH connection.

.. image:: https://de.opensuse.org/images/7/77/Paket-Download-Icon.png
   :target: https://software.opensuse.org//download.html?project=home%3AAlexander_Naumov%3Apam-accesscontrol&package=pam-accesscontrol

Dependencies
------------
``openssh``, ``pam-python``, ``python3-qt5``

Contributing
------------
You can submit or ask for improvements using github's Pull Requests or Issues.

If you're sending a patch, please make sure the `OBS`_ is still be able to build all packages.

Credits
-------

Copyright (c) 2017-2018 Alexander Naumov (alexander_naumov@opensuse.org).

Licensed under GNU GPLv3 (see docs/LICENSE file).

.. _OBS: https://build.opensuse.org/package/show/home:Alexander_Naumov:pam-accesscontrol/pam-accesscontrol
