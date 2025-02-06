# Simple UI tools for using pwdsphinx on X11

This directory contains tools that can be used on their own, or
in concert to interact with pwdsphinx.

## getpwd (depends on pinentry)

This is a simple script which uses `pinentry` from the gnupg project
to query a password and write it out to standard output. Which
`pinentry` variant you use, is up to you, it can be a curses, GTK+ or
QT interface. This should be safer than echoing a password into
pwdsphinx, since your password will not show up in your process list
nor your command line history. Use it like this:

```
getpwd | sphinx get username hostname
```

## exec-on-click.sh (depends on xinput)

This is a simple shellscript that depends on `xinput`, which waits
until a left-mouse click and then it executes whatever parameters the
script has been called with. For example:

```
echo -n "hello world" |  bin/exec-on-click.sh xdotool type --clearmodifiers '$(cat)'
```

Types `hello world` into the current window using xdotool.

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

## pipe2tmpfile 

This is a simple tool that converts the output of a pipe into a temporary file
and runs the command replacing the token `@@keyfile@@` with the filename of
temporary file, which gets deleted after the command finishes running. A simple
example to sign a file using a minisig key stored in sphinx:

```sh
  getpwd | env/bin/sphinx get minisig://user1 minisign-test-key | pipe2tmpfile minisign -S -s @@keyfile@@ -m filetosign
```

## sphinx-x11

This is a simple "script" language interpreter that integrates the
SPHINX CLI with X11. In the `sphinx-scripts` directory you can find 3
example scripts:

 - pass.sphinx <user> <host>
 - user-pass.sphinx <user> <host>
 - user-pass-otp.sphinx <user> <host>

each of these scripts waits for the user to click, then they retrieve
the relevant password (and TOTP token) before inserting it into the
form fields, navigating between them with `tab` and `enter`. You are
welcome to contribute adapted sphinx-scripts for websites that have
other login semantics. As an example the `user-pass-otp.sphinx` script
is explained below:

```
#!./sphinx-x11

wait-for-click
user
tab
pwd
tab
enter
wait-for-click
otp
enter
```

The first line specifies `sphinx-x11` as the interpreter. The script
itself then waits for the user to click (line 3), then in line 4
inserts the `user` - which is specified as the first parameter to this
script. Line 5 injects a `tab` so the next form field is
selected. Then pwdsphinx/getpwd is used to get the password for `user`
and `host` - the host being the 2nd parameter to this script. `enter`
is used to submit this form in line 8. Since this is a new form the
script waits (line 9) for the user to click in the field where the
TOTP value needs to be inserted. Then in line 10 the TOTP value is
queried using pwdsphinx/getpwd, and finally in the last line the TOTP
value is submitted by injecting `enter` into the application.

A note on the OTP support, in this interpreter/implementation an TOTP
value is assumed to be stored with a username prefixed with `otp://`,
so the first `pwd` operation uses e.g. `joe` as a username and then
for the TOTP value it uses `otp://joe` as the username.
