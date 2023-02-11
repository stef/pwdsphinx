% type-pwd(1) | tool which wraps sphinx(1) to get and type a password to an X11 application

# SYNOPSIS

```
type-pwd username hostname
```

# DESCRIPTION

This script combines `getpwd(1)`, `exec-on-click(1)` and the
`sphinx(1)` client in such a way, that it securely queries for your
master password, and then waits until you click somewhere (hopefully
into a password entry field) and then sends the password as
keystrokes. Using this mechanism you make sure your password is never
on your clipboard where malware might steal it. And also it allows to
enter your password on those sites that disable copy/pasting into
password fields.

When you click make sure you click in the password entry field where
you want the password to be entered.

# REPORTING BUGS

https://github.com/stef/pwdsphinx/issues/

# AUTHOR

Written by Stefan Marsiske.

## COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

## SEE ALSO

`sphinx(1)`, `exec-on-click(1)`,  `getpwd(1)`
