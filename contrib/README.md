# Simple UI tools for using pwdsphinx on X11

This directory contains tools that can be used on their own, or
in concert to interact with pwdsphinx.

## getpwd.sh (depends on pinentry)

This is a simple script which uses `pinentry` from the gnupg project
to query a password and write it out to standard output. Which
`pinentry` variant you use, is up to you, it can be a curses, gtk or
qt interface. This should be safer than echoing a password into
pwdsphinx, since your password will not show up in your process list
nor your command line history. Use it like this:

```
getpwd.sh | sphinx get username hostname
```

## exec-on-click.sh (depends on xinput)

This is a simple shellscript that depends on `xinput`, which waits
until a left-mouse click and then it executes whatever parameters the
script has been called with. For example:

```
echo -n "hello world" |  bin/exec-on-click.sh xdotool type --clearmodifiers '$(cat)'
```

Types `hello world` into the current window using xdotool.

You need to configure this script by running

```
xinput --list --short | fgrep pointer
```

and select from this list your mouse device which you want to be
monitored for clicking and then set the `MOUSEDEV` configuration
variable to that value. For example on Thinkpads this might be a
correct name:

```
MOUSEDEV='TPPS/2 IBM TrackPoint'
```

Writing this to one of the three config-files completes the setup:


```
echo MOUSEDEV='the name of your mouse device' >$config_file
```

where `$config_file` is one of `/etc/sphinx/mousedev`,
`~/.config/sphinx/mousedev`, or `${0%%/*}/mousedev`


## type-pwd.sh (depends on xdotool, exec-on-click and getpwd)

This script combines `getpwd.sh`, `exec-on-click.sh` and the pwdsphinx
client in such a way, that it securely queries for your master
password, and then waits until you click somewhere (hopefully into a
password entry field) and then sends the password as keystrokes. Using
this mechanism you make sure your password is never on your clipboard
where malware might steal it. And also it allows to enter your
password on those braindead stupid sites that disable copy/pasting
into password fields.

Use it as such:

```
type-pwd.sh username hostname
```

and click in the password entry field where you want the password to
be entered.

## dmenu-sphinx.sh (depends on dmenu, type-pwd.sh)

This tool builds on type-pwd.sh, it uses dmenu in order to query a
hostname, then depending if only one username or more are known by the
oracle - if only one then the next step is skipped: provides a choice
which username to use. Then `type-pwd.sh` invoked using the selected
user and hostname.
