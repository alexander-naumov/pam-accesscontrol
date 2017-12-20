#
# spec file for package pam-accesscontrol
#
# Copyright (c) 2017 Alexander Naumov <alexander_naumov@opensuse.org>
# Copyright (c) 2017 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#

Name:           pam-accesscontrol
Version:        0.92
Release:        0
License:        GPL-3.0+
Summary:        PAM-based access control system
Url:            https://github.com/alexander-naumov/pam-accesscontrol
Group:          Productivity/Security
Source:         %{name}_%{version}.tar.gz
Requires:       openssh, pam-python, python3-qt5
#BuildRequires:
#PreReq:
#Provides:
BuildArch:      noarch
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
PAM-ACCESSCONTROL is writen in python and use PAM to control login access to
the host via SSH, sddm, gdm, kdm, xdm, lightdm, and login(1).
It makes it possible to manages access for some group of users or, for example,
depend on configuration can ask user for confirmation about establishing each
new incoming SSH-connection.

%prep
%setup -c -n pam-accesscontrol
%build

%install
mkdir -p %{buildroot}/etc/pam-accesscontrol.d/
mkdir -p %{buildroot}/lib/security
mkdir -p %{buildroot}/usr/share/pam-accesscontrol
mkdir -p %{buildroot}%{_mandir}/man1
mkdir -p %{buildroot}%{_mandir}/man5

install -m 644 etc/pam-accesscontrol.d/pam-accesscontrol.conf %{buildroot}/etc/pam-accesscontrol.d/pam-accesscontrol.conf
install -m 644 lib/security/accesscontrol.py %{buildroot}/lib/security/
install -m 755 usr/share/pam-accesscontrol/windows.py %{buildroot}/usr/share/pam-accesscontrol/
install -m 755 usr/share/pam-accesscontrol/notifications.py %{buildroot}/usr/share/pam-accesscontrol/
install -m 644 docs/pam-accesscontrol.1 %{buildroot}%{_mandir}/man1/pam-accesscontrol.1
install -m 644 docs/pam-accesscontrol.d.5 %{buildroot}%{_mandir}/man5/pam-accesscontrol.d.5


%post
for i in "sddm" "login" "sshd" "lightdm" "xdm" "kdm" "gdm"; do
    if [ -f "/etc/pam.d/$i" ]; then
      echo ""
      echo "#PAM-ACCESSCONTROL configuration" >> "/etc/pam.d/$i"
      echo "auth        required     pam_python.so accesscontrol.py" >> "/etc/pam.d/$i"
      echo "session     required     pam_python.so accesscontrol.py" >> "/etc/pam.d/$i"
      echo \[DONE\] successfully configured: $i
    fi
done

%if 0%{?suse_version}
  echo "Congratualtions! PAM-ACCESSCONTROL was successfull installed."
  echo "Please run 'host +' as user root to allow notifications."
%endif

%postun
for i in "sddm" "login" "sshd" "lightdm" "xdm" "kdm" "gdm"; do
    if [ -f "/etc/pam.d/$i" ]; then
      sed -i '/accesscontrol/d' "/etc/pam.d/$i"
      sed -i '/PAM-ACCESSCONTROL/d' "/etc/pam.d/$i"
    fi
done


%files
%defattr(-,root,root)
#ChangeLog README COPYING
%dir /etc/pam-accesscontrol.d
%config /etc/pam-accesscontrol.d/pam-accesscontrol.conf
%dir /usr/share/pam-accesscontrol
/usr/share/pam-accesscontrol/*
%dir /lib/security/
/lib/security/*
%{_mandir}/man1/pam-accesscontrol.1.gz
%{_mandir}/man5/pam-accesscontrol.d.5.gz
