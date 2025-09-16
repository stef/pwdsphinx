% dmenu-sphinx(1) | dmenu-frontend for retrieving and inserting passwords from sphinx(1) into X11 applications

# NAME

dmenu-sphinx - dmenu-frontend for retrieving and inserting passwords from sphinx(1) into X11 applications

# SYNOPSIS

```
dmenu-sphinx [username] [hostname]
```

# DESCRIPTION

`dmenu-sphinx` provides an interactive interface for retrieving SPHINX passwords and automatically typing them into X11 applications. It uses `dmenu(1)` to present hostname selection menus and builds on `type-pwd(1)` for password entry.

The tool first displays cached hostnames from previous usage. If multiple usernames exist for the selected hostname, it presents a username selection menu. Otherwise, it proceeds directly to password generation. Finally, it invokes `type-pwd(1)` to type the password into the focused application.

The hostname history is cached in the file `~/.sphinx-hosts`.

# REPORTING BUGS

<https://github.com/stef/pwdsphinx/issues/>

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`sphinx(1)`, `type-pwd(1)`, `exec-on-click(1)`,  `getpwd(1)`
