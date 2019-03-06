---
layout: default
---

**/etc/pam-accesscontrol.d/pam-accesscontrol.conf** - pam-accesscontrol general configuration file.

# CONFIGURATION
To configure pam-accesscontrol you will need to fill config file. This file should
contain list of rules. Each rule has to include exactly 4 fields separated by spaces:

`<SERVICE> <OPTION> <TARGET> <PARAMETERS>`

### SERVICE
defines \fIPAM\fR service that should be managed. List of PAM services/daemons could be found
in \fB/etc/pam.d/*\fP directory. Each service could be configured via pam-accesscontrol(8)
management tool.
.PP
Special SERVICE is \fBsshd\fP. It manages incoming SSH connections (from local- and remote hosts)
by using \fIpassword\fR authentication. There is other SSH service called \fBsshd-key\fP. It is
similar to sshd, but it managed the \fIssh-public-key\fR authentication based connections only.
Both SERVICEs points to the \fB/etc/pam.d/sshd\fP file, but in configuration file should be
specified what kind of connections should be managed. It is important to understand: \fBsshd\fP
does nothing with ssh-public-key authentication and on the contrary - \fBsshd-key\fP not managed
password authentication sessions.
.RE
.PP
### OPTION
behavior for its SERVICE. It could be one of 4 types: \fIOPEN\fR, \fICLOSE\fR, \fIASK\fR
or \fINUMBER\fR. They change the access configuration.

.RS 6
\fIOPEN\fR and \fICLOSE\fR will give access for remote user or not.
.RE

.RS 6
\fIASK\fR is used to open access, but only with user confirmation. In this case local user
will be asked (by using Tk window) about permission for creating new session. After new session
will be established, remote user can easily create next sessions without new confirmations.
This will be interpreted as a same session until there is at lest one active open session.
After remote user closes last session, pam-accesscontrol calls an notification (Tk window) to
inform local user about it. After that for creating a new session it will be need to get
confirmation again.
.RE

.RS 6
\fINUMBER\fR is used to set limit for logged users. PARAMETER for this OPTION uses ":" as a
separator between value of the TARGET and value for its PARAMETER. For example, this sets
limit for 3 users from group 'lp':
.PP
.RS 7
SSHD NUMBER GROUP lp:3
.RE
.PP
Keep in mind, that it doesn't open or close access for user automaticaly. It needed to be
defined additionally. For example, this settings should be used for configuration where just
one user from group 'admin' may have SSH access:
.PP
.RS 7
SSHD OPEN GROUP admin
.br
SSHD NUMBER GROUP admin:1
.RE
.PP
Also very important to understand that NUMBER doesn't sets limits for number of sessions,
but for remote users (that can be login to this mashine) only. In other words, using
configuration above only one user from group admin can establish SSH session, but number
of sessions is not limited.
.RE
.RE

### TARGET
defines target for SERVICE. At the moment supported targets are \fIUSER\fR and
\fIGROUP\fR. GROUPs includes and supports normal POSIX groups, primary groups and LDAP
groups (from, for example, FreeIPA or Active Directory).
.RE

### PARAMETERS
this field defines values for OPTION. It's possible to set list of parameters in one line;
use "," as a separator for that. No space is needed.
.PP
This example demonstrates setting where SSH access via public-key authentication is open
for users 'tom' and 'alex' only:
.PP
.RS 7
SSHD-KEY OPEN USERS tom,alex
.RE
.PP
For NUMBER is also used ":" symbol to split values and its parameters:
.PP
.RS 7
SSHD OPEN GROUP heroes,lp
.br
SSHD NUMBER GROUP heroes:2,lp:3
.RE
.RE
.RE


.PP
 
.PP
There are also 2 very important setting values that could be defined and help with
configuration:
.PP

.RS 3
DEFAULT
.RS 4
It's posible to define default behavior by using \fIDEFAULT\fR rule. The syntax for this
rule is defferent like for other rules. It's sepatated by ":" symbol and accept only two
values: 'CLOSE' and 'OPEN'. For example:
.PP
.RS 7
DEFAULT:CLOSE
.RE
.PP
This closes all not defined situations. In other words, everything what is not defined
in config file will be automatically interpreted as not allowed (i.e. should be ignored).
And vice versa: 'OPEN' will open access for all kind of connection, if there are no other
rules listed in config file which can be suitable for.
.br
If \fIDEFAULT\fR parameter will be not found in config file at all, default behavior will
be set to 'CLOSE'. It is highly recommended to set \fIDEFAULT\fR parameter in config file.
It makes it easier to debug the access problems if any and makes configuration more
intuitive.
.PP
.RE
.RE

.RS 3
DEBUG
.RS 4
It's also possible to enable extra logs in syslog. This includes checks for return values
from most of the functions. That could be very helpful by debugging or development. To set
\fIDEBUG\fR parameter just add this line to a config file:
.PP
.RS 7
DEBUG:True
.RE
.RE
.RE

.PP
It can be helpfull to use comments in configuration file. Comments starts with the hash
character, #, and extend to the end of the physical line (exactly like for the most configuration
files in the the UNIX/Linux world).
.PP

# EXAMPLES
User A: member of group "linux-users"
.br
User B: member of groups "linux-users" and "admin"
.br
User E: member of groups "linux-users" and "admin"
.br
User F: member of group "linux-users"
.br
User C: member of groups "linux-users" and "lpadmin"

.PP
\fIConfiguration\fR 1:
.PP
.RS 5
Member of group "admin" may to login via sddm. There is no access for all next users.
.PP
.RS 7
DEFAULT:CLOSE
.br
SDDM OPEN GROUP admin
.br
SDDM NUMBER GROUP admin:1
.RE
.RE
.PP

\fIConfiguration\fR 2:
.PP
.RS 5
User A should have access via via sddm. User B can to login only via SSH with public-key
authentication only and only when user A confirm it. No other access methond for user B
should be possible. If user A allows access, user B can create more then
just one SSH-connections. For all other users it should not be possible to login
while users A and B are logged already.
.PP
.RS 7
DEFAULT:CLOSE
.br
SDDM OPEN GROUP linux-users
.br
SDDM NUMBER GROUP linux-users:1
.br
SSHD-KEY ASK GROUP admin
.br
SSHD-KEY NUMBER GROUP admin:1
.RE
.PP
That will work for user B only if user A confirms establishing of the new SSH-session.
In case you want to allow access for user B without confirmation, change option \fIASK\fR
to \fIOPEN\fR:
.PP
.RS 7
"SSHD-KEY ASK GROUP admin" => "SSHD-KEY OPEN GROUP admin"
.RE
.PP
What will happen when user from group "admin" will try to connect via SSH before
user A creates its X session and can confirm establisching SSH-session for user A?
Well... in this case establisching SSH-session for user B will be possible without
confirmation. Warning, this can be surprise somebody! It is default behavior in
version 0.96. This is not new.
.PP
\fIConfiguration\fR 3:
.PP
.RS 5
Everyone have access to all daemons via all services. Everything for everybody is open.
This is default configuration after pam-accesscontrol will be installed.
.PP
.RS 7
DEFAULT:OPEN
.RE
.RE
.PP

\fIConfiguraion\fR 4:
.PP
.RS 5
Everything is open except of SSH.
.PP
.RS 7
DEFAULT:OPEN
.br
SSHD CLOSE GROUP ALL
.br
SSHD-KEY CLOSE GROUP ALL
.RE
.RE
.PP
Group "ALL" means everyone. Use capital letters: "ALL", not "all" or "All"!

\fIConfiguraion\fR 5:
.PP
.RS 5
Everyone can to login via all services, but for establisching SSH-session confirmation is necessary.
.PP
Keep in mind, if there is no active X session (in this case nobody will be able
to confirm the opening/creating of the new SSH-session (looked X session is an active
session)), pam-accesscontrol interprets an ASK rule as OPEN. In other words, SSH access
will be open (remote users still will need to use passwords or passphrase for its
ssh-keys, i.e. standart SSH auth mechanism).
.PP
.RS 7
DEFAULT:OPEN
.br
SSHD ASK GROUP ALL
.br
SSHD-KEY ASK GROUP ALL
.RE
.RE
.PP

\fIConfiguraiton\fR 6:
.PP
.RS 5
Only members of group 'admin' can to login via SSH by using public-key authentication (without confirmation).
.PP
.RS 7
DEFAULT:CLOSE
.br
SSHD-KEY OPEN GROUP admin
.br
.RE
.PP

# BUGS
There are some problems with notification windows by using GNOME Shell and display manager "ACCESS DENIED" window by using GDM.

.SH "SEE ALSO"
.BR pam(3),
.BR pam(8),
.BR tty(4),
.BR login(1),
.BR sddm(1),
.BR sshd(8),
.BR pam-accesscontrol(8)
