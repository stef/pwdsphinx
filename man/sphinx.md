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

In general if any operation requires a master(input) password, it is
expected on standard input, and any resulting account (output)
password is printed to standard output. In the examples we use `echo`
but it is recommended to use `getpwd(1)` or similar tools to query and pass the
input password.

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

`sphinx` not only handles passwords, it is also able to handle (T)OTP
2FA and age keys. Additionally - if installed - `sphinx` also provides
access to `opaquestore(1)`, a simple tool that allows to store secrets
that need encrypted storage (like keys, phrases, or other data).

## INITIALIZING A CLIENT

```
sphinx init
```

This creates a new master key for the client, which is used to address
records on the sphinx server and authorize management operations on
those records.

You **SHOULD** back up and encrypt this master key.

If you want to use sphinx on a different device you want to copy this
master key also there. For copying this (and other settings) to the
android client `androsphinx` we have the `qr` operation, see below.

## CREATE PASSWORD

Creating a new password for a site is easy, pass your "master"
password on standard input to the client, and provide parameters like
in this example:

```
echo -n 'my input password' | sphinx create username example.com ulsd 0 ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
```

The parameters to the client are

  - Your input password on standard input. Since the input password is
    not used to input anything, you can actually use different input
    passwords for different user/site combinations. (Unlike with
    traditional password managers which have one master password that
    encrypts the whole database)
  - `create` for the operation, then
  - `username` for the username on
  - the site `example.com` then
  - the password constraints, see sections `PASSWORD RULES` and
    `PREDETERMINED PASSWORDS` for more info

If the command runs successfully - the resulting new high-entropy
output password according to the given rules is printed to the
console.

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
provide your input password on standard input to this operation.

If all goes well, there is no output expected. If anything goes wrong,
there is going to be an error message and a non-zero exit-code.

## UNDOING A PASSWORD COMMIT

If you somehow messed up and have to go back to use the old password, you can
undo committing your password using:

```
echo -n 'my master password' | sphinx undo username example.com
```

Depending on your `rwd_keys` configuration setting, you might have to
provide your master password on standard input to this operation.

If all goes well, there is no output expected, otherwise there will be
an error message and non-zero exit-code.

## DELETING PASSWORDS

In case you want to delete a password, you can do using the following
command:

```
echo -n "my master password" | sphinx delete username example.com
```

You provide the `delete` operation as the first parameter to the
client, your `username` as the 2nd and the `site` as the 3rd
parameter. This command does not provide any output on the console in
case everything goes well, otherwise an error message and an non-zero
exit code will signal a problem.

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

If you do not provide password rules, they will be defaulting to
'ulsd' and length as long as possible, which means 77 characters long
passwords using all four character classes, providing 507 bits of
entropy, way too much.

### RECOMMENDED OUTPUT PASSWORD LENGTH

It is recommended to set the output password size to maximum 12 chars
in case of `ulsd` classes enabled. If you ever have to type in this
output password on a TV remote, or in other stressful situations this
will be a big relief. 12 character long passwords with full entropy
and consisting of all possible printable ASCII chars are
computationally impossible to bruteforce on current password cracking
hardware, as they provide almost 80 bits of entropy, and 15 characters
almost 99 bits of entropy.

## PREDETERMINED OUTPUT PASSWORDS

In case for some reason you cannot use random passwords with your
account, or you want to store a "password" that you cannot change,
like a PIN code for example, or a passphrase shared with your
colleagues, you can specify a maximum 77 character long password, that
will be generated by the SPHINX client for you. In that case the
command line looks like this (note the same syntax also works for the
`change` operation)

```
echo -n 'my master password' | sphinx create username example.com "correct_battery-horse#staple"
```

In this case you cannot specify neither the accepted character
classes, nor the size, nor symbols, these will be deducted from the
predetermined password itself.

## Backward compatibility with v1 SPHINX servers/records

If you still have SPHINX records on the server that were generated using v1,
- and you want to use them -, you have to specify this server also in
the client section like you had to in v1. If there is no record found
with v2 get operations sphinx will attempt a get request for a v1
style record. If a v1 style record is found, a new v2 style record is
created automatically, so no need to check for v1 style records in
this particular case anymore.

Unless you use also other clients that are v1 onl (like androsphinx)
v1 records that are upgraded to v2 can be automatically deleted after
a succesful upgrade, for this set `delete_upgraded` to true in the
`[client]` section of your sphinx configuration. This helps server
administrators by keeping their "DB" clean, and having a means to see
how many v1 records are still not upgraded.

## OUTPUT PLUGINS (TOTP & AGE)

It is possible to "store" TOTP secrets and age secret keys using
`sphinx`. To store such a secret and have it automatically handled
correctly (e.g. TOTP verification code output instead of the secret)
just prefix your username with `otp://` for TOTP support and with
`age://` for age key support. The latter, when queried will output a
correctly formatted age private key.

## OPAQUE-Store INTEGRATION

If you have opaque-store (see https://github.com/stef/opaque-store/)
installed and configured (see `opaque-stored.cfg(5)`) correctly you
get a number of additional operations, which allow you to store
traditionally encrypted blobs of information. The following
operations will be available if opaque-store is setup correctly:

```sh
echo -n 'password' | sphinx store <keyid> file-to-store
echo -n 'password' | sphinx read <keyid>
echo -n 'password' | sphinx replace [force] <keyid> file-to-store
echo -n 'password' | sphinx edit [force] <keyid>
echo -n 'password' | sphinx changepwd [force] <keyid>
echo -n 'password' | sphinx erase [force] <keyid>
echo -n 'password' | sphinx recovery-tokens <keyid>
echo -n 'password' | sphinx unlock <keyid> <recovery-token>
```

### How does OPAQUE-Store SPHINX integration work

In all OPAQUE-Store operations we first execute a SPHINX get
operation, that calculates the password which is used with
OPAQUE. This means that the input passwords for OPAQUE will be the
strongest possible and essentially un-bruteforcable on their own
(without SPHINX). Of course online bruteforce attacks are still
possible going through SPHINX. But OPAQUE is able to detect wrong
passwords and thus can lock your record after a pre-configured amount
of failed attempts. Of course this does not apply to the operator of
an OPAQUE server, who can circumvent the locking of records. And thus:

### A WARNING: don't let one entity control enough of your SPHINX and OPAQUE-Store servers

As you can see every opaque-store op needs a password on standard
input. This password is run through SPHINX, and the output password is
used in the OPAQUE protocol as the input password. This also means,
that if you use a single server setup for both SPHINX and
OPAQUE-Store, the two servers should not be controlled by the same 3rd
party entity, otherwise this entity is able to offline-bruteforce your
SPHINX master password. If you use either of these services in a
threshold setup, and these threshold servers are controlled by
different entities, you should be ok, as long as no one controls a
threshold number of oracles/servers.

### OPAQUE-Store CLI Parameters

#### KeyId

Every operation provided by the OPAQUE-Storage (O-S) integration needs
a "keyid" parameter, this references your record stored by
O-S. Internally the client uses the configuration value `id_salt`,
together with the name of the O-S server to hash the keyid parameter
into a record id for the O-S Server. This means, that if you lose or
change your `id_salt` parameter or the name of the O-S server, all
your record ids will be different and inaccessible. So it is a good
idea to make a backup of your configuration file containing
these. Note this `id_salt` doesn't really have to be secret, although
it does provide another layer of security-by-obscurity if you do
so.

#### Forced operations

In the case that you are using a threshold setup, some operations
(`replace`, `edit`, `changepwd` and `erase`) require that all servers
successfully participate in the operation. This is to avoid, that the
records on temporarily unavailable servers remain unchanged and lead
later possibly to corruption. If you are sure however that this is ok,
you can provide a `force` parameter on the CLI which reduces the
number of servers successfully participating to the value of your
`threshold` configuration setting.

### Store an encrypted blob

```sh
getpwd | sphinx store <keyid> file-to-store
```

This simply does what it promises, stores the `file-to-store`
encrypted on the OPAQUE-Store server, using a password derived from
SPHINX. Note that this command outputs also a recovery-token, which
you should keep safe in case your record gets locked.

### Retrieving an encrypted opaquestore blob

```sh
getpwd | sphinx read <keyid>
```

Straightforward, no surprise. This gets your previously stored record
and displays it on standard output.

### Overwrite an encrypted opaquestore blob

```sh
getpwd | sphinx replace [force] <keyid> file-to-store
```

Whatever has been stored at `keyid` is now overwritten by an encrypted
`file-to-store`. This only works, if there is already something stored
at `keyid`. All servers must cooperate in this, if one or more are
unavailable this will fail, unless `force` is specified and the
threshold is matched, in which case the servers unavailable will be
corrupted from this point on.

### Edit a opaquestore blob

```sh
getpwd | sphinx edit [force] <keyid>
```

This operation fetches the file stored at `keyid` loads it into your
editor (specified by the `EDITOR` environment variable) and stores the
changes and saved file back on the same `keyid` overwriting the
original.

### Change your password on an opaquestore blob

```sh
getpwd | sphinx changepwd [force] <keyid>
```

This operation does a full change of passwords and keys. Even if you
don't change your own password that you provide to getpwd, SPHINX will
change it's own key, and thus change the output password which will be
used for the password in OPAQUE-store finally resulting in a whole new
and fresh encryption key for your file which gets re-encrypted with
that.

### Delete a stored opaquestore blob

```sh
getpwd | sphinx erase [force] <keyid>
```

Nothing surprising here, does what it promises, deletes the stored
blob referenced by the keyid.

### Get a recovery token

```sh
getpwd | sphinx recovery-tokens <keyid>
```

If your record is not locked, this operation gets you an additional
recovery token.

### Unlock a locked opaquestore blob

```sh
getpwd | sphinx unlock <keyid> <recovery-token>
```

If for some reason (someone online-bruteforcing your record, or you
forgetting your master password) your record becomes locked by the
servers, you can unlock it using a recovery token. This will also
automatically retrieve the record - unless you supply the wrong
password again.

# SPHINX CONFIGURATION

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
generated by issuing an `init` command. You **SHOULD** back up and
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

Specify `address` and `port` for backward compatibility with an old v1
server. If there is no record found with v2 get operations sphinx will
attempt a v1 style get request and see if the record is available from
"old times". If a v1 record is found a new v2 style record is created,
so no need to send a v1 get request for this particular record anymore.

`delete_upgraded` enables automatic deletion of v1 records after automatically
upgrading them to v2 records. Unless you use also other clients that are v1
only (like androsphinx) this is the recommended setting, it removes crust and
enables server operators to see if their users are finally completely v2, and
can disable v1 support.

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
ltsigkey = "32byteBase64EncodedValue=="
```

The subsections all have the the format [server.`name`]. This `name` can be
freely chosen and can be a public value. it is __important__ to never change
it, as long as you want to access your passwords on this server. This name
value is used together with other values to create unique record IDs. If you
change the name the record IDs change, and you will not be able to access your
old records.

The `host` and `port` should match what you set (or its admin publishes) in the
`oracle(1)` server.  The `ltsigkey` is the servers long-term signing key for
threshold operations this should be a base64 encoded value. Alternatively you
can also store the raw binary key in a file, which you then specify using the
`ltsigkey_path` value instead. This key only needed for threshold operation, if
you use SPHINX in a single-server setting you don't need this.

# SECURITY CONSIDERATIONS

You **SHOULD** back up and encrypt your master key. Hint you could do
this using the `qr key` operation, recording all the other important
details as well.

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

Copyright © 2024 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

https://www.ctrlc.hu/~stef/blog/posts/sphinx.html

https://www.ctrlc.hu/~stef/blog/posts/oprf.html

https://github.com/stef/opaque-store/

`oracle(1)`, `getpwd(1)`, `opaquestore(1)`
