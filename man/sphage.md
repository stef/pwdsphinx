% sphage(1) | converts 32 bytes binary data into an age(1) keypair

# NAME

sphage - converts 32 bytes binary data into an age(1) keypair

# SYNOPSIS

```
echo "32 byte high-entropy string....." | sphage privkey >/tmp/privatekey
echo "32 byte high-entropy string....." | sphage pubkey >/tmp/pubkey
```

# DESCRIPTION

This is a converter that is meant to convert the raw output of
`sphinx(1)` into a key-pair that can be used by `age(1)` allowing for
more sophisticated secrets manager setups.

# REPORTING BUGS

https://github.com/stef/pwdsphinx/issues/

# AUTHOR

Written by Stefan Marsiske.

## COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

## SEE ALSO

`sphinx(1)`
