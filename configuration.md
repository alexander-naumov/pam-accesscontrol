---
layout: default
---

**/etc/pam-accesscontrol.d/pam-accesscontrol.conf** - pam-accesscontrol general configuration file.

# CONFIGURATION
To configure pam-accesscontrol you will need to fill config file. This file should
contain list of rules. Each rule has to include exactly 4 fields separated by spaces:

```
<SERVICE> <OPTION> <TARGET> <PARAMETERS>
```

### SERVICE
defines PAM service that should be managed. List of PAM services could be found
in **/etc/pam.d/** directory. Each service could be configured via pam-accesscontrol(8)
management tool.


Special _SERVICE_ is `sshd`. It manages incoming SSH connections (from local- and remote hosts)
by using **password-authentication**. There is other SSH service called `sshd-key`. It is
similar to sshd, but it managed the **public-key-authentication** based connections only.
Both _SERVICEs_ points to the **/etc/pam.d/sshd** file, but in configuration file should be
specified what kind of connections should be managed. It is important to understand: `sshd`
does nothing with **public-key-authentication** and on the contrary - `sshd-key` not managed
**password-authentication** sessions.

### OPTION
behavior for its _SERVICE_. It could be one of the 4 types: `OPEN`, `CLOSE`, `ASK` or `NUMBER`.
They change the behavior of access configuration.

`OPEN` and `CLOSE` will open access or denied it.

`ASK` is used to open access, but only after user's confirmation. In this case local user
will be asked (by using Qt window) about allowing creating new session. After new session
will be opened, remote user can easily create next sessions without new confirmations.
This will be interpreted as a same session until there is at lest one active open session.
After remote user closes its last session, pam-accesscontrol calls an notification (Qt window)
to inform local user about it. After that confirmation will be needed again.

`NUMBER` is used to set limit for numbers of logged users. _PARAMETER_ for this OPTION uses ":"
as a separator between value of the _TARGET_ and value for its _PARAMETER_. For example, this
sets limit for 3 users for group 'lp':

```
SSHD NUMBER GROUP lp:3
```
Keep in mind, that it doesn't open or close access for user automaticaly. It needed to be
defined additionally. For example, this settings should be used for configuration where just
one user from group 'admin' may have SSH access:

```
SSHD OPEN GROUP admin
SSHD NUMBER GROUP admin:1
```

Also very important to understand that _NUMBER_ doesn't sets limits for number of sessions,
but for remote users (that can be login to this mashine) only. In other words, using
configuration above only one user from group 'admin' can establish SSH session, but number
of its sessions is not limited.

### TARGET
defines target for _SERVICE_. At the moment supported targets are `USER` and
`GROUP`. GROUPs includes and supports normal POSIX groups, primary groups and LDAP
groups (for example, from FreeIPA or Active Directory).


### PARAMETERS
this field defines values for _OPTION_. It is possible to set list of parameters in one line;
use "," as a separator for that. No space is needed.


This example demonstrates setting where SSH access via public-key authentication is open
for users 'tom' and 'alex' only:

```
SSHD-KEY OPEN USERS tom,alex
```

For _NUMBER_ is also used ":" symbol to split values and its parameters:

```
SSHD OPEN GROUP heroes,lp
SSHD NUMBER GROUP heroes:2,lp:3
```

There are also two very important special setting values that could be defined and help with
configuration:

### DEFAULT
It's posible to define default behavior by using `DEFAULT` rule. The syntax for this
rule is different like for other rules. It is sepatated by ":" symbol and accept only two
values: `CLOSE` and `OPEN`. For example:

```
DEFAULT:CLOSE
```

This closes all not defined login situations. In other words, everything what is not defined
in config file will be automatically interpreted as not allowed (i.e. should be ignored).
And vice versa: `OPEN` will open access for all kind of connection, if there are no other
rules listed in config file which can be suitable for.

If `DEFAULT` parameter not found in config file, default behavior will be set to `CLOSE`.
It is recommended to set `DEFAULT` parameter in config file. It makes it easier to debug the
access problems if any and makes configuration more intuitive.

### DEBUG
It's also possible to enable extra logs in syslog. This includes checks for return values
from most of the functions. That could be very helpful by debugging or development. To set
`DEBUG` parameter just add this line to a config file:

```
DEBUG:True
```

It can be helpfull to use comments in configuration file. Comments starts with the hash
character `#` and extend to the end of the physical line (exactly like for the most configuration
files in the the UNIX/Linux world).

# EXAMPLES
User A: member of group "linux-users"
User B: member of groups "linux-users" and "admin"
User E: member of groups "linux-users" and "admin"
User F: member of group "linux-users"
User C: member of groups "linux-users" and "lpadmin"


### Configuration 1:
Member of group "admin" may to login via sddm. There is no access for all next users.

```
DEFAULT:CLOSE

SDDM OPEN GROUP admin
SDDM NUMBER GROUP admin:1
```

### Configuration 2:
User A should have access via via sddm. User B can to login only via SSH with public-key
authentication only and only when user A confirm it. No other access methond for user B
should be possible. If user A allows access, user B can create more then
just one SSH-connections. For all other users it should not be possible to login
while users A and B are logged already.

```
DEFAULT:CLOSE

SDDM OPEN GROUP linux-users
SDDM NUMBER GROUP linux-users:1

SSHD-KEY ASK GROUP admin
SSHD-KEY NUMBER GROUP admin:1
```

That will work for user B only if user A confirms establishing new SSH session.
In case you want to allow access for user B without confirmation, change option `ASK`
to `OPEN`:

```
SSHD-KEY ASK GROUP admin 
SSHD-KEY OPEN GROUP admin
```


What will happen when user from group "admin" will try to connect via SSH before
user A creates its X session and can confirm establisching SSH-session for user A?
Well... in this case establisching SSH-session for user B will be possible without
confirmation. Warning, this can be surprise somebody! It is default behavior in
version 0.96. This is not new.

### Configuration 3:
Everyone have access to all daemons via all services. Everything for everybody is open.
This is default configuration after pam-accesscontrol will be installed.

```
DEFAULT:OPEN
```

### Configuraion 4:
Everything is open except of SSH.

```
DEFAULT:OPEN

SSHD CLOSE GROUP ALL
SSHD-KEY CLOSE GROUP ALL
```
Group `ALL` means everyone. Use capital letters: `ALL`, not "all" or "All"!

### Configuraion 5:
Everyone can to login via all services, but for establisching SSH-session confirmation is necessary.

Keep in mind, if there is no active X session (in this case nobody will be able
to confirm the opening/creating of the new SSH-session (looked X session is an active
session)), pam-accesscontrol interprets an ASK rule as OPEN. In other words, SSH access
will be open (remote users still will need to use passwords or passphrase for its
ssh-keys, i.e. standart SSH auth mechanism).
.PP
.RS 7

```
DEFAULT:OPEN

SSHD ASK GROUP ALL
SSHD-KEY ASK GROUP ALL
```

### Configuraiton 6:
Only members of group 'admin' can to login via SSH by using public-key authentication (without confirmation).

```
DEFAULT:CLOSE
SSHD-KEY OPEN GROUP admin
```


# BUGS
There are some problems with notification windows by using GNOME Shell and display manager "ACCESS DENIED" window by using GDM.

# SEE ALSO

pam(3),
pam(8),
tty(4),
login(1),
sddm(1),
sshd(8),
pam-accesscontrol(8)
