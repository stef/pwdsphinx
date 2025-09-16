% getpwd(1) | simple tool that queries a password from a user and writes it to standard output

# NAME

getpwd - simple tool that queries a password from a user and writes it to standard output

# SYNOPSIS

```
getpwd ["prompt"] | sphinx get username hostname
```

# DESCRIPTION

`getpwd` securely prompts for a password using `pinentry` from the GnuPG project and outputs it to standard output. This approach is safer than echoing passwords directly into commands, as it prevents passwords from appearing in process lists or command history.

The tool supports various `pinentry` interfaces including curses, GTK, and Qt variants, allowing you to choose the interface that best fits your desktop environment.

The parameter, `prompt`, specifies the prompt text displayed when asking for the password.

# REPORTING BUGS

<https://github.com/stef/pwdsphinx/issues/>

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`sphinx(1)`
