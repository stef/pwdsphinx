<!--
SPDX-FileCopyrightText: 2018, Marsiske Stefan

SPDX-License-Identifier: CC-BY-SA-4.0
-->

sphinx: a password **S**tore that **P**erfectly **H**ides from **I**tself (**N**o **X**aggeration)

pwdsphinx is python wrapper around libsphinx - a cryptographic password storage
as described in https://eprint.iacr.org/2015/1099

## Also on Radicle

To clone this repo on [Radicle](https://radicle.xyz), simply run:

  `rad clone rad:z3K5zSdfkoD6dytPhbk6v7mJLUojU`

## Dependencies

You need [libsphinx](https://github.com/stef/libsphinx) and [libequihash](https://github.com/stef/equihash/) for the python reference frontend.

You need also to install `pysodium` using either your OS package
manager or pip.

If you want to use also the websphinx browser extension you need to
install also an X11 variant of pinentry from the gnupg project:

 - either `apt-get install pinentry-qt`
 - or `apt-get install pinentry-gtk2`
 - or `apt-get install pinentry-gnome3`
 - or `apt-get install pinentry-fltk`

(or anything equivalent to `apt-get install` on your OS)

## Installation

`pip3 install pwdsphinx` should get you started.

## Server/Client

Since the sphinx protocol only makes sense if the "device" is
somewhere else than where you type your password, pwdsphinx
comes with a server implemented in py3 which you can host off-site
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

### sphinx - the client

This is the client that connects to the oracle to manage passwords
using the extended sphinx protocol.

#### Client Configuration

Like the server, the client can be configured changing the settings in
the `[client]` section of the config file. The `host` and `port` should
match what you set in the oracle.

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
