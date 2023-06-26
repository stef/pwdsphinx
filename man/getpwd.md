% getpwd(1) | simple tool that queries a password from a user and writes it to standard output

# NAME

getpwd - simple tool that queries a password from a user and writes it to standard output

# SYNOPSIS

```
getpwd ["prompt"] | sphinx get username hostname
```

# DESCRIPTION

This is a simple script which uses `pinentry` from the gnupg project
to query a password and write it out to standard output. Which
`pinentry` variant you use, is up to you, it can be a curses, gtk or
qt interface. This should be safer than echoing a password into
pwdsphinx, since your password will not show up in your process list
nor your command line history.

The only parameter this tool takes is a prompt to display when asking
for the password.

# REPORTING BUGS

https://github.com/stef/pwdsphinx/issues/

# AUTHOR

Written by Stefan Marsiske.

## COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

## SEE ALSO

`sphinx(1)`
