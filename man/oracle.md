% oracle(1) | server for the SPHINX password manager

# NAME

oracle - server for the SPHINX password manager

# SYNOPSIS

`oracle [init]`

# DESCRIPTION

The SPHINX protocol only makes sense if the server (called *oracle*) is located somewhere other than where you type your password. `pwdsphinx` comes with a server implemented in Python 3, which you can host off-site from your usual desktop or smartphone.

The server can be started simply by running `oracle`. It does not take any parameters.

# CONFIGURATION

The server can be configured using any of the following files:

- `/etc/sphinx/config`
- `~/.sphinxrc`
- `~/.config/sphinx/config`
- `./sphinx.cfg`

Files are parsed in the order listed above, so global settings can be overridden by per-user and per-directory settings.

Configuration is done by editing variables in the `[server]` section of the configuration file.

- `address`: Determines on what address the server is listening. The default is `localhost`: you might want to change that to a specific IP address.
- `port`: Sets the port the server is listening on. The default is `2355`. Another recommended port value is `443`, which is allowed by most firewalls, while `2355` is not.
- `ssl_key`, `ssl_cert`: Required. Have no defaults, and must be set to point at a traditional TLS certificate and secret key file. It is recommended to not use self-signed certs, but CA-signed certs that are recognized widely by browsers and other TLS clients when possible.
- `datadir`: The data directory where all the device "secrets" are stored. This defaults to `data/` in the current directory. Backup this directory regularly and securely, since the loss of this directory means users lose access to their passwords.
- `verbose`: Enables logging to standard output.
- `timeout`: Sets the TCP connection timeout. Increase for slow networks, with the caveat that this might lead to easier resource exhaustion, by blocking all workers.
- `max_kids`: Sets the maximum number of requests handled in parallel. The `timeout` config variable makes sure that all handlers are recycled in predictable time.
- `rl_decay`: Specifies the number of seconds after which a rate-limit level decays to an easier difficulty. Together with `rl_threshold` and `rl_gracetime`, these params are used to configure rate limiting.
- `rl_threshold`: Configures the number of failed attempts before increasing the difficulty level
- `rl_gracetime`: Sets the number of additional seconds allowed - beyond the max solution time fixed for a certain difficulty - before a rate-limiting puzzle expires.
- `ltsigkey`: Sets the path to the long-term signature private key. You can generate one by running `oracle init`. This will also create a public key and its Base64 encoded variant, which should be published to all potential users so that they can use your oracle in a threshold setup.

# INITIALIZING AN ORACLE

Given a configuration, the oracle can generate its own long-term signature key by running:

```
oracle init
```

This stores the private key at the location specified by `ltsigkey` and outputs the corresponding public key at the same location, with a `.pub` extension. The public key is also displayed as a Base64-encoded string on standard output.

# SECURITY CONSIDERATIONS

The `max_kids` and `timeout` settings can be used to control how many requests are served in parallel and how long each request can run. Without careful tuning, an attacker could launch a denial-of-service attack by keeping all `max_kids` connections busy.

Since the server only knows about failed authorizations for management operations (not incorrect master passwords for `get` requests), brute-force attempts can only be mitigated via rate limiting. Adjusting `rl_*` parameters allows you to make puzzles more difficult. On devices with less than 1GB RAM, you can increase the difficulty enough that they cannot solve the puzzles.

Rate limiting in general should not be noticeable, unless dozens of `get` requests are made to the same record. At the highest difficulty level, solving should take around 20–40 seconds, depending on CPU performance.

# REPORTING BUGS

<https://github.com/stef/pwdsphinx/issues/>

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2024 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`sphinx(1)`, `getpwd(1)`
