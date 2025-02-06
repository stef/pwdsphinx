% pipe2tmpfile(1) | simple tool that allows commands that expect files to work with data comming through a pipe

# NAME

pipe2tmpfile(1) - simple tool that allows commands that expect files to work with data comming through a pipe

# SYNOPSIS

```
echo input | pipe2tmpfile <command> @@keyfile@@
```

`command` will run with a temporary file containing the content `input`.

# DESCRIPTION

This is a simple tool that converts the output of a pipe into a temporary file
and runs the command replacing the token `@@keyfile@@` with the filename of
temporary file, which gets deleted after the command finishes running. A simple
example to sign a file using a minisig key stored in sphinx:

# EXAMPLE

```sh
  getpwd | env/bin/sphinx get minisig://user1 minisign-test-key | pipe2tmpfile minisign -S -s @@keyfile@@ -m filetosign
```

uses minisign to sign the file `filetosign` using the key fetched from sphinx.

# SECURITY CONSIDERATIONS

Since the output of sphinx is generally sensitive it is advised to not write it
to permanent storage. Thus pipe2tmpfile tries to store it in a tmpfs, by
default under `/run/user/$(id -u)`, however users can provide an alternative
path to store these files by setting the environment variable `keyroot`.

The temporary files are deleted after the execution of the command.

# REPORTING BUGS

https://github.com/stef/pwdsphinx/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2024 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`sphinx(1)`
