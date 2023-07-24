% sphinx-x11(1) | simple script interpreter for integrating password managers with X11

# NAME

sphinx-x11 - simple script interpreter for integrating password managers with X11

# DESCRIPTION

`sphinx-x11(1)` is a simple "script" language interpreter that
integrates the SPHINX CLI with X11.

# SPHINX-SCRIPT PARAMETERS

All `sphinx-x11(1)` scripts expect a username and a hostname as the
first and second parameter respectively.

# VOCABULARY

  - `type "text..."`: types the text into the currently focused X11 window.
  - `wait-for-click`: waits until the user clicks anywhere.
  - `user`: types the username - usually given as the first parameter
    to the sphinx-script - into the currently focused X11 window.
  - `host`: types the hostname - usually given as the second parameter
    to the sphinx-script - into the currently focused X11 window.
  - `pwd`: gets a password using `getpwd(1)` and `sphinx(1)`, and
    types it into the currently focused X11 window.
  - `otp`: gets a TOTP secret stored in `sphinx(1)` using `getpwd(1)`
    and generates the TOTP pin using `oathtool(1)`, which is then
    typed into the currently focused X11 window.
  - `tab`: types a tabulator into the current X11 window, possibly
    advancing between form-fields.
  - `enter`: sends an enter key press to the currently focused X11
    window, possibly submitting a form.

Any lines not consisting of these tokens are simply ignored.

# OTP SUPPORT

In this interpreter/implementation a TOTP value is assumed to be
stored with a username prefixed with `otp://`, so that a regular login
name can co-exist with the according TOTP secret in sphinx.

For example in a common 2FA login the first `pwd` operation uses
e.g. `joe` as a username and then for the TOTP value it uses
`otp://joe` as the username, which allows for seamless 2FA login.

# DEFAULT SCRIPTS

`sphinx-x11(1)` comes with 4 default sphinx-scripts:

 - pass.sphinx <user> <host>: gets a password using `sphinx(1)`, types
   it and submits it.
 - user-pass.sphinx <user> <host>: gets a password using `sphinx(1)`,
   types the user, then the password and submits it.
 - user-pass-otp.sphinx <user> <host>: gets a password, and a TOTP pin
   code using `sphinx(1)`, first types the username, then the
   password, then submits the form, and finally enters the TOTP pin
   and submits that as well.
 - otp.sphinx <user> <host>: gets a TOTP pin code using `sphinx(1)`
   and types and submits it.

Each of these scripts waits for the user to click, then they retrieve
the relevant password (and/or TOTP token) before inserting it into the
form fields, navigating between them with `tab` and `enter`. You are
welcome to contribute adapted sphinx-scripts for websites that have
other login semantics.

# EXAMPLE

As an example the `user-pass-otp.sphinx` script
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

The first line specifies `sphinx-x11(1)` as the interpreter. The script
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


# REPORTING BUGS

https://github.com/stef/pwdsphinx/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`sphinx(1)`, `type-pwd(1)`, `exec-on-click(1)`,  `getpwd(1)`
