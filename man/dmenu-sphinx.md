% dmenu-sphinx(1) | dmenu-frontend for retrieving and inserting passwords from sphinx(1) into X11 applications

# NAME

dmenu-sphinx - dmenu-frontend for retrieving and inserting passwords from sphinx(1) into X11 applications

# SYNOPSIS

```
type-pwd username hostname
```

# DESCRIPTION

This tool builds on `type-pwd(1)`, it uses `dmenu(1)` in order to
query a hostname, then depending if only one or more usernames are
known by the oracle - if only one then the next step is skipped:
provides a choice which username to use. Then `type-pwd(1)` is invoked
using the selected user and hostname.

This tool cashes the hostnames it was used with in the file
`~/.sphinx-hosts`.

# REPORTING BUGS

https://github.com/stef/pwdsphinx/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`sphinx(1)`, `type-pwd(1)`, `exec-on-click(1)`,  `getpwd(1)`
