install:
	mkdir -p /usr/share/pam-accesscontrol/img
	install -m500 usr/share/pam-accesscontrol/*.py /usr/share/pam-accesscontrol/
	install -m644 usr/share/pam-accesscontrol/NEWS* /usr/share/pam-accesscontrol/
	install -m644 usr/share/pam-accesscontrol/TODO /usr/share/pam-accesscontrol/
	install -m644 usr/share/pam-accesscontrol/img/* /usr/share/pam-accesscontrol/img/

	mkdir -p /usr/sbin/
	install -m500 usr/sbin/pam-accesscontrol /usr/sbin/pam-accesscontrol

	mkdir -p /usr/share/man/man8
	cp docs/pam-accesscontrol.8 /usr/share/man/man8/pam-accesscontrol.8.gz
	mkdir -p /usr/share/man/man5
	cp docs/pam-accesscontrol.conf.5 /usr/share/man/man5/pam-accesscontrol.conf.5.gz
	cp docs/mail-notification.conf.5 /usr/share/man/man5/mail-notification.5.gz
	
	mkdir -p /etc/pam-accesscontrol.d/
	install -m600 etc/pam-accesscontrol.d/* /etc/pam-accesscontrol.d/

	mkdir -p /lib/security
	install -m500 lib/security/accesscontrol.py /lib/security/accesscontrol.py
