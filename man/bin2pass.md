% bin2pass(1) | converts binary input to passwords

# NAME

bin2pass - converts binary input to passwords

# SYNOPSIS

```
bin2pass [d|u|l] [<max size>] [<symbols>] <binary
```

# DESCRIPTION

`bin2pass` reads standard input, and accepts three optional parameters (note
this is the same syntax as accepted by `sphinx(1)`):

 - a combination of the letters "uld" enabling upper-, lower-case letters and
   digits respectively. If this is not provided `bin2pass` defaults to "uld".

 - a number setting the maximum length of the password to be converted to. Note
   if you specify a larger number than is possible to generate from the input the
   output will be padded by leading "A" characters. The default is the longest
   possible output depending on the input

 - a string listing all the symbols allowed in the password. Any of the
   following is allowed (and this is also the default if not specified):

```
| !"#$%&'()*+,-./:;<=>?@[\]^_`{}~
```

Please note that <space> is allowed, and also be careful in quoting special
characters that might be interpreted by your shell, such as `"`, `!`, `\`,
etc...

# EXAMPLES

Generate the longest possible random password from /dev/random, with the
resulting password having characters from digits, lower- and upper-case letters
and the <space> and * symbols.

```
dd if=/dev/random bs=1 count=30 | ./pwdsphinx/bin2pass.py " *"
```

# REPORTING BUGS

https://github.com/stef/pwdsphinx/issues/

# AUTHOR

Written by Stefan Marsiske.

## COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

## SEE ALSO

`sphinx(1)` 
