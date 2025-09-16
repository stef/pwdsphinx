% type-pwd(1) | tool which wraps sphinx(1) to get and type a password to an X11 application

# NAME

type-pwd - tool which wraps sphinx(1) to get and type a password to an X11 application

# SYNOPSIS

```
type-pwd username hostname
```

# DESCRIPTION

`type-pwd` combines `getpwd(1)`, `exec-on-click(1)`, and `sphinx(1)` to create a secure password entry workflow. It first prompts for your master password, then waits for you to click on a password field before typing the password as keystrokes.

This approach ensures that your password never appears in the clipboard where malware could steal it. It also works on websites that disable copy and paste functionality in password fields.

When prompted to click, make sure you click directly in the password entry field where you want the password entered.

# REPORTING BUGS

<https://github.com/stef/pwdsphinx/issues/>

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`sphinx(1)`, `exec-on-click(1)`,  `getpwd(1)`
