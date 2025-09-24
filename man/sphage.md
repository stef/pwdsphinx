% sphage(1) | converts 32 bytes binary data into an age(1) keypair

# NAME

sphage - converts 32 bytes binary data into an age(1) keypair

# SYNOPSIS

```
echo "32 byte high-entropy string....." | sphage privkey >/tmp/privatekey
echo "32 byte high-entropy string....." | sphage pubkey >/tmp/pubkey
```

# DESCRIPTION

`sphage` converts the raw output of `sphinx(1)` into a cryptographic key pair compatible with [age](https://age-encryption.org). It can also convert an age secret key into its corresponding age public key. This enables integration between SPHINX and age-based encryption workflows for sophisticated secrets management setups.

# REPORTING BUGS

https://github.com/stef/pwdsphinx/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later https://gnu.org/licenses/gpl.html.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`sphinx(1)`
