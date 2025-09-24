% pipe2tmpfile(1) | simple tool that allows commands that expect files to work with data coming through a pipe

# NAME

pipe2tmpfile - simple tool that allows commands that expect files to work with data coming through a pipe

# SYNOPSIS

```
echo input | pipe2tmpfile <command> @@keyfile@@ [additional args...]
```

The `command` will run with a temporary file containing the piped content, where `@@keyfile@@` is replaced with the temporary file path.

# DESCRIPTION

`pipe2tmpfile` is a utility that bridges the gap between commands that output data to stdout and commands that require file input. It reads data from standard input, writes it to a secure temporary file, and then executes a specified command with the temporary file path substituted for the `@@keyfile@@` token.

This tool is particularly useful when working with sensitive data like cryptographic keys or passwords that should not be written to permanent storage. The temporary file is automatically deleted after the command finishes running, ensuring no sensitive data remains on disk.


# EXAMPLE

Sign a file using a minisign key stored in SPHINX:

```sh
getpwd | sphinx get minisig://user1 minisign-test-key | pipe2tmpfile minisign -S -s @@keyfile@@ -m filetosign
```

This command:

1. Prompts for your master password via `getpwd`
2. Retrieves the `minisign` private key from SPHINX
3. Writes the key to a secure temporary file
4. Runs `minisign` to sign `filetosign` using the temporary key file
5. Automatically deletes the temporary key file

# SECURITY CONSIDERATIONS

Since the output of SPHINX is generally sensitive, it is advised not to write it
to permanent storage. Thus, `pipe2tmpfile` tries to store it in a temporary
file storage. By default, this is stored under `/run/user/$(id -u)`.
However, users can provide an alternative path to store these files
by setting the environment variable `keyroot`.

The temporary files are deleted after the execution of the command.

# REPORTING BUGS

https://github.com/stef/pwdsphinx/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2024 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later https://gnu.org/licenses/gpl.html.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`sphinx(1)`
