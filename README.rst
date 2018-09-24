=========================================
 pam-accesscontrol
=========================================
PAM-accesscontrol is the highly intellectual and easily configurable system to control
access to host via PAM interfaces. It makes it possible to manages access for some user,
group of users or LDAP-groups (supports FreeIPA and Active Directory) by adding just
one line to the config file.  It makes it possible to be notifyed about establisching
each new incoming connection and allow or not allow it (by using notification window).
PAM-accesscontrol supports and recognizes SSH password and public key authentication
and uses Syslog for every login-events.
This is the last security layer for enterprises and personal use.

.. image:: https://de.opensuse.org/images/7/77/Paket-Download-Icon.png
   :target: https://software.opensuse.org//download.html?project=home%3AAlexander_Naumov%3Apam-accesscontrol&package=pam-accesscontrol

We provide packages for many different GNU/Linux systems to make it easy to install or update pam-accesscontrol.

Screenshots
-----------
Kubuntu 18.04, sddm:
    .. image:: https://paste.opensuse.org/images/61202325.jpg
        :alt: sddm is CLOSEd for specific user
        :width: 100%
        :align: center

openSUSE Leap 15.1, XFCE, SSH password authentication:
    .. image:: https://paste.opensuse.org/images/40629189.jpg
        :alt: notification window for SSH
        :width: 100%
        :align: center

Ubuntu 18.04, Unity, SSH pub-key authentication:
    .. image:: https://paste.opensuse.org/images/74975662.jpg
        :alt: Ubuntu
        :width: 100%
        :align: center

Debian 9.5, slim (Simple Login Manager):
    .. image:: https://paste.opensuse.org/images/44154633.jpg
        :alt: Debian
        :width: 100%
        :align: center

Contributing
------------
You can submit or ask for improvements using github's Pull Requests or Issues.

If you're going to send a patch, please make sure that dev `OBS`_ project is still be able to build packages.

Credits
-------

Copyright (c) 2017-2018 Alexander Naumov (alexander_naumov@opensuse.org).

Licensed under GNU GPLv3 (see `LICENSE`_ file).



.. _LICENSE: https://github.com/alexander-naumov/pam-accesscontrol/blob/master/LICENSE
.. _OBS: https://build.opensuse.org/package/show/home:Alexander_Naumov:DEV-pam-accesscontrol/pam-accesscontrol
