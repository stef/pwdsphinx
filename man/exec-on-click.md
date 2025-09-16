% exec-on-click(1) | simple tool that executes command when a left mouse-click is detected

# NAME

exec-on-click - simple tool that executes command when a left mouse-click is detected

# SYNOPSIS

```
exec-on-click <command>
```

# DESCRIPTION

`exec-on-click` is a simple tool that waits for a left mouse click and then executes whatever parameters the script has been called with.

# EXAMPLE

```
echo -n "hello world" |  exec-on-click xdotool type --clearmodifiers '$(cat)'
```

Types `hello world` into the current window using [xdotool](https://github.com/jordansissel/xdotool), a program that lets you simulate keyboard input and mouse activity.

# REPORTING BUGS

<https://github.com/stef/pwdsphinx/issues/>

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`sphinx(1)`
