<!--
SPDX-FileCopyrightText: 2018, Marsiske Stefan

SPDX-License-Identifier: CC-BY-SA-4.0
-->

sphinx: a password **S**tore that **P**erfectly **H**ides from **I**tself (**N**o **X**aggeration)

pwdsphinx is python wrapper around libsphinx - a cryptographic password storage
as described in https://eprint.iacr.org/2015/1099

## Also on Radicle

To clone this repo on [Radicle](https://radicle.xyz), simply run:

  `rad clone rad:z3rjK2hk7ckb1thexdsuyaM7e4FwS`

## Dependencies

You need [liboprf](https://github.com/stef/liboprf) and [libequihash](https://github.com/stef/equihash/) for the python reference frontend.

You need also to install `pysodium` and `pyoprf` using either
your OS package manager or pip.

If you want to use also the websphinx browser extension you need to
install also an X11 variant of pinentry from the gnupg project:

 - either `apt-get install pinentry-qt`
 - or `apt-get install pinentry-gtk2`
 - or `apt-get install pinentry-gnome3`
 - or `apt-get install pinentry-fltk`

(or anything equivalent to `apt-get install` on your OS)

If you want to store other "secrets" that are longer than just 30-40 bytes, you
can install opaque-store: https://github.com/stef/opaque-store/ using

  `pip3 install opaquestore`

which depends additionally on libopaque: https://github.com/stef/libopaque

## Installation

`pip3 install pwdsphinx` should get you started.

## Server/Client

Since the SPHINX protocol only makes sense if the "device" is
somewhere else than where you type your password, pwdsphinx
comes with a server implemented in python3 which you can host off-site
from your usual desktop/smartphone. Also a client is supplied which is
able to communicate with the server and manage passwords.

Both the client and the server can be configured by any of the
following files:

 - `/etc/sphinx/config`
 - `~/.sphinxrc`
 - `~/.config/sphinx/config`
 - `./sphinx.cfg`

Files are parsed in this order, this means global settings can be
overridden by per-user and per-directory settings.

### oracle - the server

pwdsphinx comes with a python reference implementation of a extended sphinx
server called oracle.

The server can be "configured" by changing the variables in the
`[server]` section of the config file.

The `address` is the IP address on which the server is listening,
default is `localhost` - you might want to change that.

The `port` where the server is listening is by default 2355.

`datadir` specifies the data directory where all the device "secrets"
are stored, this defaults to "data/" in the current directory. You
might want to back up this directory from time to time to an encrypted
medium.

`verbose` enables logging to standard output.

`timeout` sets the timeout for any connection the server keeps open.

`max_kids` sets the number maximum requests handled in parallel. The
`timeout` config variable makes sure that all handlers are recycled in
predictable time.

`rl_decay` specifies the number of seconds after which a ratelimit level
decays to an easier difficulty.

`rl_threshold` increase the difficulty of ratelimit puzzles if not
decaying.

`rl_gracetime` gracetime in seconds added to the expcted time to solve
a rate-limiting puzzle.

Change these settings to fit your needs. Starting the server
can be done simply by:

```
oracle
```

For more information see the man-page `oracle(1)`

### sphinx - the client

This is the client that connects to the oracle to manage passwords
using the extended sphinx protocol.

#### Client Configuration

The client can be configured changing the settings in the `[client]`
section of the config file.

The datadir (default: `~/.sphinx`) variable holds the location for your client
parameters. Particularly it contains a masterkey which is used to derive
secrets. The master key - if not available - is generated by issuing an init
command. You **should** back up and encrypt this master key.

`rwd_keys` toggles if the master password is required for
authentication of management operations. If it is False it protects
against offline master password bruteforce attacks - which is also a
security guarantee of the original SPHINX protocol. The drawback is
that for known (host,username) tuples the seeds/blobs can be
changed/deleted by an attacker if the clients masterkey is available
to them. But neither the master nor the account password can leak this
way. This is merely a denial-of-service vector. If rwd_keys is True,
then this eliminates the denial-of-service vector, but instead
eliminates the offline-bruteforce guarantee of the SPHINX
protocol. Note that the oracle is oblivious to this setting, this is
purely a client-side toggle, in theory it is possible to have
different settings for different "records" on the oracle.

`validate_password` Stores a check digit of 5 bits in on the oracle,
this helps to notice most typos of the master password, while
decreasing security slightly.

`userlist` option (default: True) can disable the usage of userlists. This
prohibits the server to correlate all the records that belong to the same
sphinx user relating to the same host. The cost of this, is that the user has
to remember themselves which usernames they have at which host.

For more detailed information consult the man-page `sphinx(1)`

#### Operations

The client provides the following operations: Create, Get, Change, Commit,
Undo, List and Delete. All operations need a username and a site this
password belongs to, even if they're only empty strings.

#### Create password

Creating a new password for a site is easy, pass your "master"
password on standard input to the client, and provide parameters like
in this example:

```
echo -n 'my master password' | sphinx create username example.com ulsd 0 ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
```

The parameters to the client are `create` for the operation, then `username`
for the username on the site `example.com` then a combination of the
letters `ulsd` and the `0` for the size of the final password. The letters
`ulsd` stand in order for the following character classes: `u` upper-case
letters, `l` lower-case letters, `s` symbols and `d` for digits. The `s` is a
short-cut to allow all of the symbols, if you have a stupid server that limits
some symbols, you can specify the allowed symbols explicitly. Currently these
are the symbols supported (note the leading space char):

```
 !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
```

Be careful, if you specify these on the command-line you'll have to
escape the quotes you use for enclosing this list and possibly the
backslash char that is also part of this list. In the `create
username` example above the symbols are correctly escaped, in case you
need to copy/paste them.

If you do not provide password rules, they will be defaulting to 'ulsd' and
length as long as possible.

If the command runs successfully - the resulting new high-entropy password
according to the given rules is printed to the console.

In case for some reason you cannot use random passwords with your
account, or you want to store a "password" that you cannot change,
like a PIN code for example, or a passphrase shared with your
colleagues, you can specify a maximum 44 character long password, that
will be generated by the SPHINX client for you. In that case the
command line looks like this (note the same syntax also works for the
`change` operation)

```
echo -n 'my master password' | sphinx create username example.com "correct_battery-horse#staple"
```

In this case you cannot specify neither the accepted character
classes, nor the size, nor symbols.

Note1, since the master password is not used to encrypt anything, you can
actually use different "master" passwords for different user/site combinations.

Note2, using echo is only for demonstration, you should use something like this
instead (getpwd is available from the contrib directory):
```
getpwd.sh | sphinx create username example.com ulsd 0
```

#### Get password

Getting a password from the sphinx oracle works by running the
following command:

```
echo -n 'my master password' | sphinx get username example.com
```

Here again you supply your master password on standard input, provide
the `get` operation as the first parameter, your `username` as the 2nd
and the `site` as the 3rd parameter. The resulting password is
returned on standard output.

#### Change password

You might want to (or are forced to regularly) change your password, this
is easy while you can keep your master password the unchanged (or you
can change it too, if you want). The command is this:

```
echo -en 'my master password\nnew masterpassword' | sphinx change username example.com 'ulsd' 0 ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
```

Here again you supply your master password on standard input, but
separated by a new-line you also provide the new master password. The
new master password can be the same as the old, but can also be a new
password if you want to change also the master password. You provide
the `change` operation as the first parameter to the client, your
`username` as the 2nd and the `site` as the 3rd parameter.  You also
can provide similar password generation rule parameters that were also
used to create the original password, in case your account has new
password rules and you want/have to accommodate them. Your new
password is returned on standard output.

#### Committing a changed password

After changing the password, you will still get the old password when running
`get`. To switch to use the new password you have to commit the changes with

```
echo -n 'my master password' | sphinx commit username example.com
```

#### Undoing a password commit

If you somehow messed up and have to go back to use the old password, you can
undo committing your password using:

```
echo -n 'my master password' | sphinx undo username example.com
```

#### Deleting passwords

In case you want to delete a password, you can do using the following
command:

```
echo -n "my master password" | sphinx delete username example.com
```

You provide the `delete` operation as the first parameter to the
client, your `username` as the 2nd and the `site` as the 3rd
parameter. This command does not provide anything on standard output
in case everything goes well.

#### QR code config

In case you want to use phone with the same sphinx server, you need to export
your config to the phone via a QR code.

```
sphinx qr
```

Will display a QR code containing only public information - like the server
host and port, and if you use rwd_keys. This is mostly useful if you want to
share your setup with a friend or family.

If you want to connect your own phone to the setup used with pwdsphinx, you
also need to export your client secret in the QR code:

```
sphinx qr key
```

This contains your client secret, and you should keep this QR code
confidential. Make sure there is no cameras making copies of this while this QR
code is displayed on your screen.

If for whatever reason you want to display the QR code as an SVG, just append
the `svg` keyword to the end of the `sphinx qr` command.

## OPAQUE-Store client-integration

If you have opaque-store installed and configured correctly you get a number of
additional operations, which allow you to store traditionally encrypted blobs
of information. For a gentle introduction how this works using OPAQUE, have a
look at this post:

`https://www.ctrlc.hu/~stef/blog/posts/How_to_recover_static_secrets_using_OPAQUE.html`

The following operations will be available if opaque-store is setup correctly:

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

### A Warning: don't let one entity control your SPHINX and OPAQUE-Store servers

As you can see every opaque-store op needs a password on standard
input. This password is run through SPHINX, and the output password is
used in the OPAQUE protocol as the input password. This also means,
that if you use a single server setup for both SPHINX and
OPAQUE-Store, the two servers should not be controlled by the same
entity, otherwise this entity is able to offline-bruteforce your
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
idea to make a backup of your configuration file containing these.

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

### Retrieving an encrypted blob

```sh
getpwd | sphinx read <keyid>
```

Straightforward, no surprise.

### Overwrite an encrypted blob

```sh
getpwd | sphinx replace [force] <keyid> file-to-store
```

Whatever has been stored at `keyid` is now overwritten by an encrypted
`file-to-store`. This only works, if there is already something stored
at `keyid`. All servers must cooperate in this, if one or more are
unavailable this will fail, unless `force` is specified and the
threshold is matched, in which case the servers unavailable will be
corrupted from this point on.

### Edit a file

```sh
getpwd | sphinx edit [force] <keyid>
```

This operation fetches the file stored at `keyid` loads it into your
editor (specified by the `EDITOR` environment variable) and stores the
changes and saved file back on the same `keyid` overwriting the
original.

### Change your password

```sh
getpwd | sphinx changepwd [force] <keyid>
```

This operation does a full change of passwords and keys. Even if you
don't change your own password that you provide to getpwd, SPHINX will
change it's own key, and thus change the output password which will be
used for the password in OPAQUE-store finally resulting in a whole new
and fresh encryption key for your file which gets re-encrypted with
that.

### Delete a stored file

```sh
getpwd | sphinx erase [force] <keyid>
```

Nothing surprising here, does what is written on the package.

### Get a recovery token

```sh
getpwd | sphinx recovery-tokens <keyid>
```

If your record is not locked, this operation gets you an additional
recovery token, that you can use later to unlock your record, should
it become locked.

### Unlock a locked record

```sh
getpwd | sphinx unlock <keyid> <recovery-token>
```

If for some reason (someone online-bruteforcing your record, or you
forgetting your master password) your record becomes locked by the
servers, you can unlock it using a recovery token.

## X11 frontend

You can find a bunch of shell-scripts that are based on
`pinentry-(gtk|qt)`, `xinput`, `xdotool` and `dmenu`, the top-level
entry to these is the `dmenu-sphinx.sh` script, which stores its
history of entered hostnames in `~/.sphinx-hosts` - if the hosts are
in any way sensitive, you might want to link this file to
`/dev/null`. The `contrib/README.md` should give you an idea of how
else to combine these scripts.

## Credits

This project was funded through the NGI0 PET Fund, a fund established
by NLnet with financial support from the European Commission's Next
Generation Internet programme, under the aegis of DG Communications
Networks, Content and Technology under grant agreement No 825310.

This project was funded through the e-Commons Fund, a fund established by NLnet
with financial support from the Netherlands Ministry of the Interior and
Kingdom Relations.
[<img src="https://nlnet.nl/image/logos/minbzk.logo.svg" alt="Logo The Netherlands Ministry of the Interior and Kingdom Relations" width="20%" />](https://www.rijksoverheid.nl/ministeries/ministerie-van-binnenlandse-zaken-en-koninkrijksrelaties)

Everlasting gratuity to asciimoo, dnet, jonathan and hugo for their
contributions, patience, and support.
