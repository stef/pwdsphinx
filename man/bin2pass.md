% bin2pass(1) | converts binary input to passwords

# NAME

bin2pass - converts binary input to passwords

# SYNOPSIS

```
bin2pass [d|u|l] [<max size>] [<symbols>] <binary
```

# DESCRIPTION

`bin2pass` converts binary input from standard input into human-readable passwords. It accepts three optional parameters using the same syntax as `sphinx(1)`:

- **Character set**: A combination of letters "uld" enabling upper-case letters, lower-case letters, and digits respectively. Defaults to "uld" if not specified.

- **Maximum length**: Sets the maximum password length. If you specify a length larger than possible from the input, the output will be padded with leading "A" characters. Defaults to the longest possible output from the input.

- **Symbol set**: A string listing all symbols allowed in the password. The default symbol set includes:

```
| !"#$%&'()*+,-./:;<=>?@[\]^_`{}~
```

Note that spaces are allowed in the symbol set. Be careful to properly quote special characters that your shell might interpret, such as `"`, `!`, and `\`.

# EXAMPLES

Generate the longest possible random password from `/dev/random`, with the resulting password having characters from digits, lowercase and uppercase letters, and the `space` and `*` symbols.

```
dd if=/dev/random bs=1 count=32 | ./pwdsphinx/bin2pass.py " *"
```

# REPORTING BUGS

<https://github.com/stef/pwdsphinx/issues/>

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`sphinx(1)`
