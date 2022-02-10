# Simple UI tools for using pwdsphinx on X11

This directory contains three tools that can be used on their own, or
in concert to interact with pwdsphinx.

## getpwd.sh

This is a simple script which uses `pinentry` from the gnupg project
to query a password and write it out to standard output. Which
`pinentry` variant you use, is up to you, it can be a curses, gtk or
qt interface. This should be safer than echoing a password into
pwdsphinx, since your password will not show up in your process list
nor your command line history. Use it like this:

```
getpwd.sh | sphinx get username hostname
```

## exec-on-click.sh

This is a simple shellscript that depends on `xinput`, which waits
until a left-mouse click and then it executes whatever parameters the
script has been called with. For example:

```
echo -n "hello world" |  bin/exec-on-click.sh xdotool type --clearmodifiers '$(cat)'
```

Types `hello world` into the current window using xdotool.

## type-pwd.sh

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
