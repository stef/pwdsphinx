# Getting started

So you want to start using SPHINX for handling your passwords. Great, Welcome!

First you need to decide if you want to host your own server (we call
it oracle), or you want to use someone elses oracle. It's ok to use
someone elses server, as we say the oracle can be hosted by your worst
nightmare enemy, they will not learn anything about your passwords[1].

It is important to note, that if you want to use sphinx, your client
needs to be able to connect to the oracle.

## Installing the sphinx CLI client

If you are on debian or derivates a simple
```
% sudo apt install pwdsphinx
```

should suffice and you can skip over to the next section to configure the client.
But before skipping you might also want to install these optional dependencies:
```
% apt install pinentry-gtk2 xdotool xinput
```

If you are not on debian derivates, you need to build two dependencies
manually. Let's start with libsphinx:

```
% git clone https://github.com/stef/libsphinx
% cd libsphinx/src
% sudo apt install install python3 libsodium libsodium-dev
% sudo PREFIX=/usr make install
```

We also need libequihash:

```
% git clone https://github.com/stef/equihash
% cd equihash
% sudo PREFIX=/usr make install
```

And finally install the client itself:

```
% pip install pwdsphinx
```

Dependencies might also needed for some things:

```
% apt install pinentry-gtk2 xdotool xinput
```

(replace `apt install` and the package names with whatever equivalent
your distro provides)

## Configuring the sphinx CLI client

Create a config file `~/.sphinxrc` and insert the correct address and
port for the server (oracle) you are going to use:

```
[client]
address = your.sphinx-server.tld
port = 443
timeout = 3
```

Now you should be ready to initialize your sphinx client:

```
% sphinx init
```

This will create a file `~/.sphinx/masterkey`, you should make a
backup of this file, and if you intend to use sphinx on other devices
sharing the same passwords on them, you must copy this file there as
well. If you intend to use `androsphinx` our android sphinx client,
you can also do:

```
sphinx qr key
```

And have this qr-code read by the androsphinx client to use the same
config as you have setup here.

You should be ready to go:

```
echo -n "password" | sphinx create testuser testhost
```

This should give you a long very random password as output. You can
now check if you get the same password back, but since echoing
passwords on the command line is not very smart, let's try with a tool
that comes with pwdsphinx: `getpwd`:

```
getpwd | sphinx get testuser testhost
```

This should pop up a password query window, where you should enter
'password' as the password, the response should be the long random
password that was returned when you used the create command.

And you can now also try to delete this test password, as you surely
don't want to litter around:

```
sphinx delete testuser testhost
```

You might wonder, why you don't need a password for deletion - that
actually depends on the `rwd_keys` setting, read about that in the man
page. However deletion does require that the masterkey in `~/.sphinx/`
is actually correct.

Now if you do again (being lazy and not using `getpwd`):

```
echo -n "password" | sphinx get testuser testhost
```
You should get an error.

Congrats, you just setup sphinx! Read up in the man pages
(https://github.com/stef/pwdsphinx/tree/master/man) more about how to
get the most out of sphinx.

## Setting up a Firefox addon

First install the sphinx CLI client - see the section above on more
info on that.

Then install the addon from the mozilla addons store:
https://addons.mozilla.org/en-US/firefox/addon/websphinx/

The WebSphinx addon also requires the installation of a native
messaging host - which is terminology and it really means backend.

Websphinx consists of two parts, the frontend which is the addon. And the backend which handles everything.

You can install the addon  from the [firefox addon store](https://addons.mozilla.org/en-US/firefox/addon/websphinx/).

The WebSphinx addon requires the installation of a native messaging host - which is terminology and it really means backend.

You will need to install a graphical pinentry,

   - either sudo apt-get install pinentry-qt
   - or sudo apt-get install pinentry-gtk2
   - or sudo apt-get install pinentry-gnome3
   - or sudo apt-get install pinentry-fltk

(or anything equivalent to apt-get install on your OS)

And set the pinentry variant if it is not invoked with
`/usr/bin/pinentry` in your sphinx config file in the `websphinx`
section

Your sphinx config file can be in a couple of locations:
 - globally: `/etc/sphinx/config`
 - for your user: `~/.sphinxrc`
 - or also:`~/.config/sphinx/config`
 - and always in the current directory.

To set the pinentry path, add or modify to have a section like this:

```
[websphinx]
pinentry=/usr/bin/pinentry-gtk-2
```

### Native Messaging Host Manifest

Copy [*websphinx.json*](https://github.com/stef/websphinx-firefox/raw/master/websphinx.json), depending on your browser to finish the installation:

- Linux/BSD
  - User only: `~/.mozilla/native-messaging-hosts/websphinx.json`
  - System-wide: `/usr/{lib,lib64,share}/mozilla/native-messaging-hosts/websphinx.json`
  - MacOS: `/Library/Application Support/Mozilla/NativeMessagingHosts/websphinx.json`

You need to change *%PATH%* in *websphinx.json* so it refers to *websphinx.py* which came with pwdsphinx.

1. `mkdir -p ~/.mozilla/native-messaging-hosts`
2. `curl -Lo ~/.mozilla/native-messaging-hosts/websphinx.json https://github.com/stef/websphinx-firefox/raw/master/websphinx.json`

if you followed this guide, `websphinx` should be installed in `/usr/bin` and you should replace the `%PATH%` in `~/.mozilla/native-messaging-hosts/websphinx.json` to `/usr/bin` so the file looks like this:

```
{
  "name": "websphinx",
  "description": "Host for communicating with pwdphinx",
  "path": "/usr/bin/websphinx",
  "type": "stdio",
  "allowed_extensions": [
    "sphinx@ctrlc.hu"
  ]
}

```

### Final step

Restart your browser in which the addon is installed and enjoy.

## Setting up a Chrome derivate addon (including ms edge, opera, brave, etc)

Websphinx consists of two parts, the frontend which is the addon. And
the backend which handles everything.

First install the sphinx CLI client, see the above for more information on that.

WebSphinx is not in the Chrome Web Store, if you want to install the addon
follow these steps (this applies to all Operating Systems):

 1. Create a directory on your filesystem containing the files in the
    websphinx directory. 
 2. Start your browser if it is not running,
 3. open [chrome://extension](chrome://extension) in your browser,
 4. enable `Developer Mode`,
 5. `Load Unpacked Extension` and provide the directory created in step 1.,
 6. If all went well, you should get a yellowyish sphinx button.

The WebSphinx addon requires the installation of a native messaging
host - which is terminology and it really means backend.

You will need to install a graphical pinentry,
   - either sudo apt-get install pinentry-qt
   - or sudo apt-get install pinentry-gtk2
   - or sudo apt-get install pinentry-gnome3
   - or sudo apt-get install pinentry-fltk

(or anything equivalent to apt-get install on your OS)

And set the pinentry variant if it is not invoked with
`/usr/bin/pinentry` in your sphinx config file in the `websphinx`
section

Your sphinx config file can be in a couple of locations:
 - globally: `/etc/sphinx/config`
 - for your user: `~/.sphinxrc`
 - or also:`~/.config/sphinx/config`
 - and always in the current directory.

To set the pinentry path, add or modify to have a section like this:

```
[websphinx]
pinentry=/usr/bin/pinentry-gtk-2
```

### Native Messaging Host Manifest

Copy [*websphinx.json*](https://github.com/stef/websphinx-firefox/raw/master/websphinx.json), depending on your browser to finish the installation:

- Linux/BSD
  - Per-user: `~/.config/{google-chrome,chromium}/NativeMessagingHosts/websphinx.json`
  - System: `/etc/{opt/chrome,chromium}/native-messaging-hosts/websphinx.json`
- MacOS
  - Per-user: `~/Library/Application Support/{Google/Chrome,Chromium}/NativeMessagingHosts/websphinx.json`
  - System-wide: `/Library/{Google/Chrome,Chromium}/NativeMessagingHosts/websphinx.json`

You need to change *%PATH%* in *websphinx.json* so it refers to *websphinx.py* which came with pwdsphinx.

Assuming you have chromium follow these steps (otherwise replace chromium with google-chrome, or even possibly opera?)

1. `mkdir -p ~/.config/chromium/NativeMessagingHosts`
2. `curl -Lo ~/.config/chromium/NativeMessagingHosts/websphinx.json https://github.com/stef/websphinx-chrom/raw/master/websphinx.json`

if you followed this guide, `websphinx` should be installed in `/usr/bin` and you should replace the `%PATH%` in `~/.config/chromium/NativeMessagingHosts/websphinx.json` to `/usr/bin` so the file looks like this:

```
{
  "name": "websphinx",
  "description": "Host for communicating with Sphinx",
  "path": "/usr/bin/websphinx",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://ojbhlhidchjkmjmpeonendekpoacahni/"
  ]
}

```

### Final step

Restart your browser in which the addon is installed and enjoy.

## Hosting your own oracle

Great! You should host your own oracle, and make it available also to
all your friends and family! The recommended way to do so is to
dedicate cheap and small single-board-computer to this task, which
does nothing else. An old Raspberry Pi 1 is enough, the oracle does
not use much resources.

## Installation

You need to install sphinx, either by using `pip`:

```
pip install pwdsphinx
```

or on Debian derivates:

```
apt install pwdsphinx
```

### Getting a TLS certificate using nginx and letsencrypt

First you need to generate an account and a domain key:

```
openssl genrsa 4096 > account.key
openssl genrsa 4096 > domain.key
```

Then you neeed to create a certificate signing request (CSR) for your
domains. For a single domain you can use:
```
openssl req -new -sha256 -key domain.key -subj "/CN=yoursite.com" > domain.csr
```

If you have multiple domains (like www.yoursite.com and yoursite.com) and a new openssl, then:

```
openssl req -new -sha256 -key domain.key -subj "/" -addext "subjectAltName = DNS:yoursite.com, DNS:www.yoursite.com" > domain.csr
```

Or if you have an old openssl < 1.1.1:
```
openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")) > domain.csr
```

Now you need nginx, and a challenges director it can serve:
```
apt install nginx
mkdir -p /var/www/challenges/
```
The configuration of nginx is the following:
```
# Example for nginx
server {
    listen 80;
    server_name yoursite.com www.yoursite.com;

    location /.well-known/acme-challenge/ {
        alias /var/www/challenges/;
        try_files $uri =404;
    }

    ...the rest of your config
}
```

And finally use acme-tiny to get our signed certificate
```
apt install acme-tiny
acme_tiny --account-key ./account.key --csr ./domain.csr --acme-dir /var/www/challenges/ > ./signed_chain.crt
```

Tada! you should have a file called `signed_chain.crt` which contains
your cert, and the file `domain.key` which you generated at the
beginning is your secret key for the oracle.

## Configuration

When you have a TLS cert and key, you can start configuring the
oracle. A full configuration file for the oracle looks as follows:

```
[server]
# the IP address the server is listening on
#address="127.0.0.1"

# the port on which the server is listening, use 443 if available, so that
# the oracle can be accessed from behind tight firewalls
#port=2355

# ssl key - no default must be specified
ssl_key="server.der"

# ssl cert - no default must be specified
ssl_cert="cert.pem"

# tcp connection timeouts, increase in case you have bad networks, with the
# caveat that this might lead to easier resource exhaustion - blocking all
# workers.
#timeout=3

# how many worker processes can run in parallel
# max_kids=5

# the root directory where all data is stored
#datadir= "/var/lib/sphinx"

# whether to produce some output on the console
#verbose=false

# decay ratelimit after rl_decay seconds
#rl_decay= 1800

# increase hardness after rl_threshold attempts if not decaying
#rl_threshold= 1

# when checking freshness of puzzle solution, allow this extra
# gracetime in addition to the hardness max solution time
#rl_gracetime=10
```

You need to set the `address` to whatever IP address you want the
oracle to be listening on. And you should set the `port` if possible
to 443, that will enable you to have always access to the oracle when
you are on the go, since other ports might very well be firewalled,
but port 443 is very-very rarely. You also need to set the `ssl_key`
to the file `domain.key` , and the `ssl_cert` to the file
`signed_chain.crt` both from the previous section "getting a tls cert..."

The rest of the config settings you don't have to touch. When done,
simply run `oracle`, this will start the server in the foreground.

Use whatever your distro provides to daemonize and log the output of
servers to have the server automatically started at reboot.

Congratulations! Now invite your friends (and enemies!) to use your
instance :) You might also want to setup the whole thing as a tor
hidden service, so you can protect the privacy of your users even
better, but how to do so is left as an exercise to the dear reader.


[1] The only thing they can learn is the frequency how often you
interact with a certain password, and which passwords belong to the
same user and host, for example if you have an admin and a
non-privileged account at the same host the oracle user could find out
that these two are related. Also whoever is hosting the oracle can
mount a denial-of-service against you by not responding or corrupting
their answers. But your passwords would be safe, nevertheless. Even if
their "database" leaks to the internet, or criminals.
