% sphinx-x11(1) | simple script interpreter for integrating password managers with X11

# NAME

sphinx-x11 — simple script interpreter for integrating password managers with X11

# DESCRIPTION

`sphinx-x11(1)` is a simple "script" language interpreter that
integrates the SPHINX CLI with X11.

# SPHINX-SCRIPT PARAMETERS

All `sphinx-x11(1)` scripts expect a username and a hostname as the
first and second parameter respectively.

# VOCABULARY

- `type "text..."`: Types the given text into the currently focused X11 window
- `wait-for-click`: Waits until the user clicks anywhere
- `user`: Types the username (usually given as the first parameter to the sphinx script) into the currently focused X11 window
- `host`: Types the hostname (usually given as the second script parameter) into the currently focused X11 window
- `pwd`: Gets a password via `getpwd(1)` and `sphinx(1)`, then types it into the currently focused X11 window
- `otp`: Calculates the current Time-based One-Time Password (TOTP) pin code using an OTP secret stored in `sphinx(1)` using `getpwd(1)`, then types it into the currently focused X11 window.
- `tab`: Types a tab character into the currently focused X11 window, often moving between form fields.
- `enter`: Sends an Enter key press into the focused X11 window, usually submitting a form
- `gethost`: Waits for a left mouse click on a browser window, copies the URL from the address bar, extracts the hostname, and stores it in the internal `$host` variable for use with `host` or `pwd` defined above.
- `getuser`: Runs `sphinx list $host`. If multiple users are found, it presents them in a dmenu widget. If/when one user is found/selected, it is set as an internal `$user` variable which can then be used with `user` or `pwd` defined above.

Any lines not consisting of these tokens are simply ignored.

# OTP SUPPORT

In this implementation, a TOTP value is stored with a username prefixed by `otp://` so that a regular username can co-exist with its TOTP secret in SPHINX.

For example, in a common two-factor authentication (2FA) login, the first `pwd` operation might use `joe` as the username, and the TOTP value would be retrieved with `otp://joe` as the username, which allows for seamless 2FA login.

# DEFAULT SCRIPTS

`sphinx-x11(1)` ships with five default scripts. On Debian-based systems, these use a `sx11-` prefix instead of the `.sphinx` extension.

- **pass.sphinx <user> <host>**: Gets a password using `sphinx(1)`, types it, and submits it.
- **user-pass.sphinx <user> <host>**: Gets a password using `sphinx(1)`, types the username, and then submits it.
- **user-pass-otp.sphinx <user> <host>**: Gets a password, and a TOTP pin code using `sphinx(1)`, types the username, the password, then submits the form, and finally enters the TOTP pin and submits again.
- **otp.sphinx <user> <host>**: Gets a TOTP pin using `sphinx(1)` and types and submits it.
- **getacc-user-pass.sphinx**: Waits for a click on a browser window, from which it gets the target `host`. It uses this together with `sphinx list` to lists users associated with the host. Then, it waits for another click in the username input field of a login form, gets a password using `sphinx(1)`, types the username, password, and submits. This script is convenient but carries phishing risks if a malicious site manipulates the clipboard. Use this script very carefully. At the moment, this security problem is not fixed since there is no simple way to get the current tab's URL from a browser securely via a web extension.

All of these scripts wait for user interaction before retrieving
passwords (and/or TOTP tokens) and entering them, navigating with
`tab` and `enter`. You are welcome to contribute adapted sphinx
scripts for websites that have other login semantics.

# EXAMPLE

The following example demonstrates the `user-pass-otp.sphinx` script:

```
#!sphinx-x11

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

**Explanation:**

- Line 1:  Specifies `sphinx-x11(1)` as the script interpreter.
- Line 3:  Waits for the user to click.
- Line 4:  Types the username (first script parameter).
- Line 5:  Sends a `tab` key to move to the next form field.
- Line 6:  Retrieves and types the password for the specified `user` and `host` (second script parameter).
- Line 7:  Sends another `tab` key to move focus.
- Line 8:  Presses `enter` to submit the form.
- Line 9:  Waits for the user to click in the TOTP input field of the next form.
- Line 10:  Retrieves the TOTP value via `pwdsphinx/getpwd` and types it.
- Line 11:  Presses `enter` to submit the TOTP form.

# REPORTING BUGS

https://github.com/stef/pwdsphinx/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later https://gnu.org/licenses/gpl.html.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`sphinx(1)`, `type-pwd(1)`, `exec-on-click(1)`,  `getpwd(1)`
