% sphinx(1) | command-line client for the SPHINX password manager

# NAME

sphinx - command-line client for the SPHINX password manager

# SYNOPSIS

`sphinx` init

echo "password" | `sphinx` create \<user> \<site> [\<u\>\<l\>\<d\>\<s\>] [\<size>] [\<symbols>] [\<target password>]

echo "password" | `sphinx` get \<user> \<site>

echo -e "oldpassword\nnewpassword" | `sphinx` change \<user> \<site> [\<u\>\<l\>\<d\>\<s\>] [\<size>] [\<symbols>] [\<target password>]

[ echo "password" | ] `sphinx` commit  \<user> \<site>

[ echo "password" | ] `sphinx` undo  \<user> \<site>

[ echo "password" | ] `sphinx` delete \<user> \<site>

`sphinx` list \<site>

`sphinx` qr [\<svg>] [\<key>]

# DESCRIPTION

SPHINX -- password Store that Perfectly Hides from Itself (No Xaggeration) --
is an information-theoretically secure cryptographic password storage
protocol with strong security guarantees, as described in the 2015 paper
"Device-Enhanced Password Protocols with Optimal Online-Offline Protection" by
Jarecki, Krawczyk, Shirvanian, and Saxena (https://ia.cr/2015/1099).

`sphinx` is the command-line client for the SPHINX protocol, it
provides access to all operations over the life-cycle of a password:
init, create, get, change, undo, commit, delete. Additionally it
provides also operations that make this more user-friendly: listing of
users associated with a host and export of the configuration using a
qr code.

In general if any operation requires a master(input) password, it is
expected on standard input, and any resulting account (output)
password is printed to standard output. In the examples we use `echo`
but it is recommended to use `getpwd(1)` or similar tools to query and pass the
input password.

## INITIALIZING A CLIENT

```
sphinx init
```

This creates a new master key for the client, which is used to address
records on the sphinx server and authorize management operations on
those records.

You **should** back up and encrypt this master key.

If you want to use sphinx on a different device you want to copy this
master key also there. For copying this (and other settigns) to the
android client `androsphinx` we have the `qr` operation, see below.

## CREATE PASSWORD

Creating a new password for a site is easy, pass your "master"
password on standard input to the client, and provide parameters like
in this example:

```
echo -n 'my master password' | sphinx create username example.com ulsd 0 ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
```

The parameters to the client are

  - Your master password on standard input. Since the master password
    is not used to encrypt anything, you can actually use different
    "master" passwords for different user/site combinations.
  - `create` for the operation, then
  - `username` for the username on
  - the site `example.com` then
  - the password constraints, see sections `PASSWORD RULES` and
    `PREDETERMINED PASSWORDS` for more info

If the command runs successfully - the resulting new high-entropy password
according to the given rules is printed to the console.

## GET PASSWORD

Getting a password from the sphinx oracle works by running the
following command:

```
echo -n 'my master password' | sphinx get username example.com
```

You supply your master password on standard input, provide the `get`
operation as the first parameter, your `username` as the 2nd and the
`site` as the 3rd parameter. The resulting password is returned on
standard output.

## CHANGE PASSWORD

You might want to (or are forced to regularly) change your password,
this is easy while you can keep your master password unchanged (or
you can change it too, if you want). The command is this:

```
echo -en 'my master password\nnew masterpassword' | sphinx change username example.com 'ulsd' 0 ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
```

You supply your current master password on standard input, and
separated by a new-line you also provide the new master password. The
new master password can be the same as the old, but can also be a new
password if you want to change also the master password.

You provide the `change` operation as the first parameter to the
client, your `username` as the 2nd and the `site` as the 3rd
parameter.  You also can provide similar password generation rule
parameters that were also used to create the original password, in
case your account has new password rules and you want/have to
accommodate them. For more information see the `PASSWORD RULES` and
`PREDETERMINED PASSWORDS` sections below.

Your new new password is returned on standard output. __IMPORTANT__ this
only creates a new output password, but does not activate it. Running a `get`
operation will still respond with the previous password, to activate the new
password, you need to run a `commit` operation, see the next section:

## COMMITTING A CHANGED PASSWORD

After changing the password, you will still get the old password when
running the `get` operation. To switch to use the new password you
have to commit the changes with

```
echo -n 'my master password' | sphinx commit username example.com
```

Depending on your `rwd_keys` configuration setting, you might have to
provide your master password on standard input to this operation.

If all goes well, there is no output expected.

## UNDOING A PASSWORD COMMIT

If you somehow messed up and have to go back to use the old password, you can
undo committing your password using:

```
echo -n 'my master password' | sphinx undo username example.com
```

Depending on your `rwd_keys` configuration setting, you might have to
provide your master password on standard input to this operation.

If all goes well, there is no output expected.

## DELETING PASSWORDS

In case you want to delete a password, you can do using the following
command:

```
echo -n "my master password" | sphinx delete username example.com
```

You provide the `delete` operation as the first parameter to the
client, your `username` as the 2nd and the `site` as the 3rd
parameter. This command does not provide anything on standard output
in case everything goes well.

Depending on your `rwd_keys` configuration setting, you might have to
provide your master password on standard input to this operation.

## QR CODE CONFIG

In case you want to use phone with the same sphinx server, you need to
export your config to the phone via a QR code.

```
sphinx qr
```

Will display a QR code containing only public information - like the
server host and port, and whether you use rwd_keys. This is mostly
useful if you want to share your setup with a friend or family.

If you want to connect your own phone to the setup used with
pwdsphinx, you also need to export your client secret in the QR code:

```
sphinx qr key
```

This contains your client secret, and you should keep this QR code
confidential. Make sure there is no cameras making copies of this while this QR
code is displayed on your screen.

If for whatever reason you want to display the QR code as an SVG, just append
the `svg` keyword to the end of the `sphinx qr` command.

## PASSWORD RULES

When creating or changing passwords you can specify rules limiting the
size and characters allowed in the output password. This is specified
as follows:

The letters `ulsd` stand in order for the following
character classes:
  - `u` upper-case letters,
  - `l` lower-case letters,
  - `s` symbols and
  - `d` for digits.

The `s` is a short-cut to allow all of the symbols, if you
are limited by the server which symbols to use, you can specify the
allowed symbols explicitly. Currently these are the symbols supported
(note the leading space char):

```
 !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
```

Be careful, if you specify these on the command-line you'll have to
escape the quotes you use for enclosing this list and possibly the
backslash char that is also part of this list. In the `create
username` example above the symbols are correctly escaped, in case you
need to copy/paste them.

For examples how to use these see the section "CREATE PASSWORD" or
"CHANGE PASSWORD".

### DEFAULT RULES

If you do not provide password rules, they will be defaulting to 'ulsd' and
length as long as possible.

## PREDETERMINED OUTPUT PASSWORDS

In case for some reason you cannot use random passwords with your
account, or you want to store a "password" that you cannot change,
like a PIN code for example, or a passphrase shared with your
colleagues, you can specify a maximuxm 38 character long password, that
will be generated by the SPHINX client for you. In that case the
command line looks like this (note the same syntax also works for the
`change` operation)

```
echo -n 'my master password' | sphinx create username example.com "correct_battery-horse#staple"
```

In this case you cannot specify neither the accepted character
classes, nor the size, nor symbols, these will be deducted from the
predetermined password itself.

# CONFIGURATION

The client can be configured by any of the following files:

 - `/etc/sphinx/config`
 - `~/.sphinxrc`
 - `~/.config/sphinx/config`
 - `./sphinx.cfg`

Files are parsed in this order, this means global settings can be
overridden by per-user and per-directory settings.

The client can be configured changing the settings in the `[client]`
and the `[servers]` sections of the config file. 

The `datadir` (default: `~/.sphinx`) variable holds the location for
your client parameters. Particularly it contains a masterkey which is
used to derive secrets. The master key - if not available - is
generated by issuing an `init` command. You **should** back up and
encrypt this master key.

`rwd_keys` toggles if the master password is required for
authentication of management operations.

The oracle is oblivious to this setting, this is purely a client-side
toggle, in theory it is possible to have different settings for
different "records" on the oracle.

`validate_password` Stores a check digit of 5 bits in on the oracle,
this helps to notice most typos of the master password, while
decreasing security slightly.

The `userlist` option (default: True) can disable the usage of userlists. This
prohibits the server to correlate all the records that belong to the same
sphinx user relating to the same host. The cost of this, is that the user has
to remember themselves which usernames they have at which host.

The `threshold` option must specify the number of servers necessary to operate
sphinx. If the `[servers]` section contains more than two entries, this value
must be greater than 1 and less than the number of servers listed in the
`[servers]` section: 1 < threshold < len(servers).

The `[servers]' section contains subsections for each server like this:

```
[servers]
[servers.zero]
host="localhost"
port=10000
ltsigkey = "zero.pub"
```

The subsections all have the the format [server.`name`]. This `name` can be
freely chosen and can be a public value. it is __important__ to never change
it, as long as you want to access your passwords on this server. This name
value is used together with other values to create unique record IDs. If you
change the name the record IDs change, and you will not be able to access your
old records.

The `host` and `port` should match what you set in the `oracle(1)` server.  The
`ltsigkey` is the servers long-term signing key for threshold operations. This
key only needed for threshold operation, if you use SPHINX in a single-server
setting you don't need this. 

# SECURITY CONSIDERATIONS

You **should** back up and encrypt your master key.

The `rwd_keys` configuration setting, if set to False protects against
offline master password bruteforce attacks - which is also a security
guarantee of the original SPHINX protocol.

The drawback is that for known (host,username) pairs the according
record can be changed/deleted by an attacker if the clients masterkey
is available to them. However neither the master nor the account
password can leak this way. This is merely a denial-of-service attack
vector. If `rwd_keys` is set to True, then this eliminates the
denial-of-service vector, but also negates the offline-bruteforce
guarantee of the SPHINX protocol. This setting is really a compromise
between availability of account passwords versus the confidentiality
of your master password.

The `validate_password` configuration setting if enabled, decreases
security slightly (by 5 bits). In general it should be safe to enable.

The `userlist` configuration setting is by default enabled, and allows a server
operator to correlate records that belong to the same SPHINX user on the same
online service. If you have multiple accounts on an online service and all of
them are handled by the same SPHINX server, the server operator can take note
when a userlist record is updated and which SPHINX record belongs to this
operation. This leaks some information, that can be used by an adversarial
server operator to correlate records.

In this man page we are using echo only for demonstration, you should
use something like this instead (or even directly `getpwd(1)` from the
contrib directory if you are not interested in customizing):

```
echo GETPIN | pinentry | grep '^D' | cut -c3- | sphinx create username example.com ulsd 0
```

Using pinentry you can go fancy and do double password input, and even have
something checking password quality for you, check it out, it's quite
versatile.

# REPORTING BUGS

https://github.com/stef/pwdsphinx/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2023 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

https://www.ctrlc.hu/~stef/blog/posts/sphinx.html

https://www.ctrlc.hu/~stef/blog/posts/oprf.html

`oracle(1)`, `getpwd(1)`
