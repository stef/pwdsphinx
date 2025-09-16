# Getting Started with SPHINX

So you want to start using SPHINX for handling your passwords. Great, welcome!

SPHINX is a cryptographic password storage protocol that uses client-server architecture. The server (also called the *oracle*) stores only cryptographic blobs that are useless without your master password. Even if compromised, your actual passwords remain secure. The client combines your master password with the server's response to regenerate your actual passwords deterministically.
You can either use an existing server, where the server operator learns nothing about your passwords or host your own server, giving you complete control over your infrastructure.

When using someone else's server, the only thing they can learn is the
frequency of how often you interact with a certain password, and which
passwords belong to the same user and host. For example, if you have an
admin and a non-privileged account at the same host, the oracle user
could find out that these two are related. Also, whoever is hosting the oracle can
mount a denial-of-service attack against you by not responding or corrupting
their answers. But your passwords would be safe, nevertheless. Even if
their "database" leaks to the internet, or to criminals.

**Note:** To use SPHINX, your client needs to be able to connect to the oracle.

## Quick Start

### Step 1. Install Your SPHINX Client

**Debian/Ubuntu/Kali and derivatives:**

```bash
sudo apt install pwdsphinx
```

On Debian or derivatives, the above command should suffice and
you can skip over to the next section to learn how to configure the client.

You might also want to install these optional dependencies, which help
with supporting the browser extension:

```bash
apt install pinentry-gtk2 xdotool xinput
```

pinentry is a small collection of dialog programs
that allows reading passphrases and PIN numbers in a secure manner.
xdotool helps with keyboard/mouse automation, while xinput provides
input device control.

**Other Unix-like systems:**
For non-Debian derivates, you need to build two dependencies
manually, liboprf and libequihash.

liboprf is a library for Oblivious Pseudorandom Functions (OPRFs), including
support for threshold OPRFs. To install:

```bash
git clone https://github.com/stef/liboprf
cd liboprf/src
sudo apt install python3 python3-dev pkg-config libsodium libsodium-dev
sudo PREFIX=/usr make install
```

libequihash provides memory-hard proof-of-work with fast verification.
To install, run:

```bash
git clone https://github.com/stef/equihash
cd equihash
sudo PREFIX=/usr make install
```

And finally, install the client itself:

```
pip install pwdsphinx
```

Dependencies might also be needed for some things like
browser extension support:

```
% apt install pinentry-gtk2 xdotool xinput
```

Replace `apt install` and the package names with whatever equivalent
your distro provides. pinentry is a small collection of dialog programs
that allows reading passphrases and PIN numbers in a secure manner.
xdotool helps with keyboard/mouse automation, while xinput provides
input device control.

### Step 2: Configure Your Client

Create a configuration file `~/.sphinxrc` and insert the correct address and
port for the server (oracle) you are going to use:

```ini
[client]
address = your.sphinx-server.tld
port = 443
timeout = 3
```

Replace `your.sphinx-server.tld` with your chosen SPHINX server.
If you don't have one, you can [use a public server](https://sphinx.pm/servers.html).

### Step 3: Initialize Your Client

```bash
sphinx init
```

This creates a file `~/.sphinx/masterkey`. **Make a backup of this file!** If you
intend to use SPHINX on other devices while sharing the same passwords on them,
you must copy this file to these devices as well.

If using andropshinx, our Android SPHINX client, you can export your setup with:

```bash
sphinx qr key
```

This creates a QR code that can be read by androsphinx, allowing the
app to use the same configuration as you have set up above.

Scan the second QR code with [androsphinx](https://github.com/dnet/androsphinx) Android app.

### Step 4: Test Your Setup

Create a test password:

```bash
echo -n "password" | sphinx create testuser testhost
```

This should give you a long very random password as output. You can
now check if you get the same password back. Since echoing
passwords on the command line is not very smart, let's try with a tool
that comes with pwdsphinx, `getpwd`:

```bash
getpwd | sphinx get testuser testhost
```

This should pop up a password query window, where you should enter
'password' as the password. The response should be the long random
password that was returned when you used the create command.

Assuming you won't need this anymore, clean up the test:

```bash
sphinx delete testuser testhost
```

You might wonder why you don't need a password for deletion. That
actually depends on the `rwd_keys` setting. Read about this setting in
[the sphinx(1) man page](./man/sphinx.md). However, deletion does
require that the masterkey in `~/.sphinx/` is actually correct.

Now if you do again (being lazy and not using `getpwd`):

```
echo -n "password" | sphinx get testuser testhost
```

You should get an error.

Congrats, you just setup sphinx! Read up in the [man pages](./man) more
about how to get the most out of sphinx.

## Setting Up Browser Extensions

SPHINX provides browser extensions for Firefox and Chrome/Chromium
that enable seamless password filling on websites.

websphinx consists of two parts: the frontend (which is the add-on to install from
the browser extension store) and the backend (which handles everything).
The backend is actually a native messaging host that communicates with the browser extension.

### Prerequisites

Both browser extensions require:

1. **SPHINX CLI client** installed (see above)
2. **Pinentry** for secure password input:

   ```bash
   # Install any one of these, using the equivalent of `apt-get` on your operating system:
   sudo apt-get install pinentry-qt        # For KDE/Qt environments
   sudo apt-get install pinentry-gtk2      # For older GNOME/GTK environments
   sudo apt-get install pinentry-gnome3    # For modern GNOME environments
   sudo apt-get install pinentry-fltk      # Lightweight option
   ```

### Firefox Extension

#### 1. **Install the extension:**

You can install the addon from the [Firefox add-on store](https://addons.mozilla.org/en-US/firefox/addon/websphinx/).

#### 2. **Configure pinentry path**

Your SPHINX config file can be in a couple of locations:

- globally: `/etc/sphinx/config`
- for your user: `~/.sphinxrc`
- or also: `~/.config/sphinx/config`
- and always in the current directory.

Set the pinentry variant if it is not invoked with `/usr/bin/pinentry` in your config file in the `[websphinx]` section.

   ```ini
   [websphinx]
   pinentry=/usr/bin/pinentry-gtk-2
   ```

#### 3. **Install native messaging host:**

1. **Create directory for native messaging host:**

   ```bash
   mkdir -p ~/.mozilla/native-messaging-hosts
   ```

2. **Download the configuration file:**

   ```bash
   curl -Lo ~/.mozilla/native-messaging-hosts/websphinx.json \
     https://github.com/stef/websphinx-firefox/raw/master/websphinx.json
   ```

3. **Edit the configuration file** to point to the actual websphinx executable:
   - Open `~/.mozilla/native-messaging-hosts/websphinx.json`
   - Replace `%PATH%` with `/usr/bin`
   - The file should look like this:

     ```json
     {
       "name": "websphinx",
       "description": "Host for communicating with pwdsphinx",
       "path": "/usr/bin/websphinx",
       "type": "stdio",
       "allowed_extensions": [
         "sphinx@ctrlc.hu"
       ]
     }
     ```

**Alternative installation paths:**

- System-wide installation: `/usr/{lib,lib64,share}/mozilla/native-messaging-hosts/websphinx.json`
- MacOS: `/Library/Application Support/Mozilla/NativeMessagingHosts/websphinx.json`

#### 5. Final step

Restart your browser in which the add-on is installed and enjoy.

### Chrome/Chromium Extension

Chromium browsers include Microsoft Edge, Opera, Brave and more.

WebSphinx is not in the Chrome Web Store, so manual installation is required:

#### 1. **Get the extension files**

Download or clone the extension from the [websphinx-chrom repository](https://github.com/stef/websphinx-chrom).

#### 2. **Install in Developer Mode**

1. Open `chrome://extensions` in your browser
2. Enable **Developer Mode**
3. Click **Load Unpacked Extension**
4. Select the directory containing the extension files
5. You should see a yellowish sphinx button appear

#### 3. **Configure pinentry**

This is the same as in the Firefox, [explained above](#firefox-extension).

#### 4. **Install native messaging host:**

1. **Create directory for native messaging host** depending on your browser:

   ```bash
   # For Chromium:
   mkdir -p ~/.config/chromium/NativeMessagingHosts
   # For Google Chrome:
   mkdir -p ~/.config/google-chrome/NativeMessagingHosts
   ```

2. **Download the configuration file:**

   ```bash
   # For Chromium:
   curl -Lo ~/.config/chromium/NativeMessagingHosts/websphinx.json \
     https://github.com/stef/websphinx-chrom/raw/master/websphinx.json
   # For Google Chrome:
   curl -Lo ~/.config/google-chrome/NativeMessagingHosts/websphinx.json \
     https://github.com/stef/websphinx-chrom/raw/master/websphinx.json
   ```

3. **Edit the configuration file** to point to the actual websphinx executable:
   - Open the websphinx.json file you just downloaded
   - Replace `%PATH%` with `/usr/bin`
   - The file should look like this:

     ```json
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

**Alternative installation paths:**

- System-wide installation: `/etc/{opt/chrome,chromium}/native-messaging-hosts/websphinx.json`
- MacOS: `/Library/Application Support/{Google/Chrome,Chromium}/NativeMessagingHosts/websphinx.json`

### 5. Final step

Restart your browser in which the add-on is installed and enjoy.

## Hosting your own oracle

You should host your own oracle, and make it available also to
all your friends and family! The SPHINX protocol only makes
sense if the oracle is located somewhere other than where you
type your password. The recommended way to do so is to dedicate
a cheap and small single-board computer to this task, which
does nothing else. The oracle does not use much resources, so
an old Raspberry Pi 1 is enough.

### Installation

**From source:**

```bash
pip install pwdsphinx
```

**Debian/Ubuntu and derivatives:**

```bash
sudo apt install pwdsphinx
```

## Getting a TLS Certificate Using Let's Encrypt

A TLS certificate is required for the SPHINX oracle to operate securely.
This section guides you through obtaining a certificate using Let's Encrypt and nginx.

### Step 1: Generate the Required Keys

First, generate an account key and a domain key:

```bash
openssl genrsa 4096 > account.key
openssl genrsa 4096 > domain.key
```

### Step 2: Create a Certificate Signing Request (CSR)

Choose one of the following options based on your needs:

**For a single domain:**

```bash
openssl req -new -sha256 -key domain.key -subj "/CN=yoursite.com" > domain.csr
```

**For multiple domains with OpenSSL ≥ 1.1.1:**
If you have multiple domains (like `www.yoursite.com` and `yoursite.com`):

```bash
openssl req -new -sha256 -key domain.key -subj "/" -addext "subjectAltName = DNS:yoursite.com, DNS:www.yoursite.com" > domain.csr
```

**For multiple domains with OpenSSL < 1.1.1:**

```bash
openssl req -new -sha256 -key domain.key -subj "/" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:yoursite.com,DNS:www.yoursite.com")) > domain.csr
```

### Step 3: Set Up Nginx for Domain Verification

Install nginx and create the `challenges` directory:

```bash
sudo apt install nginx
sudo mkdir -p /var/www/challenges/
```

Configure nginx by editing `/etc/nginx/sites-available/default` (or create a new config):

```nginx
server {
    listen 80;
    server_name yoursite.com www.yoursite.com;  # Replace with your domain(s)

    location /.well-known/acme-challenge/ {
        alias /var/www/challenges/;
        try_files $uri =404;
    }

    # The rest of your configurations can go here
}
```

Enable the configuration and restart nginx:

```bash
sudo ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/
sudo systemctl restart nginx
```

### Step 4: Obtain the Certificate

Install and use acme-tiny to get your signed certificate:

```bash
sudo apt install acme-tiny
acme_tiny --account-key ./account.key --csr ./domain.csr --acme-dir /var/www/challenges/ > ./signed_chain.crt
```

### Step 5: Verify Your Certificate

Tada! you should have a file called `signed_chain.crt` which contains
your cert, and the file `domain.key` which you generated at the
beginning is your secret key for the oracle.
These files will be used in the SPHINX oracle configuration in the next section.

## Configuration

When you have a TLS cert and key, you can start configuring the
oracle. The oracle can be configured using any of the following files:

- `/etc/sphinx/config`
- `~/.sphinxrc`
- `~/.config/sphinx/config`
- `./sphinx.cfg`

Files are parsed in the order listed above, so global settings can be overridden by per-user and per-directory settings.

Configuration is done by editing variables in the `[server]` section of the configuration file. A full configuration file for the oracle looks as follows:

```
[server]
# Determines on what address the server is listening. The default is localhost
# -- you might want to change that to whatever IP address you want the
# oracle to be listening on.
#address="127.0.0.1"

# Sets the port the server is listening on. The default is 2355. Another
# recommended port value is 443, which is allowed by most firewalls, while
# 2355 is not. You should set this to 443 if possible, as it will enable
# you to have always access to the oracle when you are on the go, since
# other ports might very well be firewalled, but port 443 is very rarely blocked.
#port=2355

# Required. Have no defaults, and must be set to point at a traditional TLS
# certificate and secret key file. Set ssl_key to the file domain.key and
# ssl_cert to the file signed_chain.crt both from the previous section
# "Getting a TLS Certificate Using Let's Encrypt". It is recommended to not
# use self-signed certs, but CA-signed certs that are recognized widely by
# browsers and other TLS clients when possible.
ssl_key="domain.key"
ssl_cert="signed_chain.crt"

# Sets the TCP connection timeout. Increase for slow networks, with the caveat
# that this might lead to easier resource exhaustion, by blocking all workers.
#timeout=3

# Sets the maximum number of requests handled in parallel. The timeout config
# variable makes sure that all handlers are recycled in predictable time.
#max_kids=5

# The data directory where all the device "secrets" are stored. This defaults
# to `data/` in the current directory. Backup this directory regularly and
# securely, since the loss of this directory means users lose access to their
# passwords.
#datadir="/var/lib/sphinx"

# Enables logging to standard output.
#verbose=false

# Specifies the number of seconds after which a rate-limit level decays to an
# easier difficulty. Together with rl_threshold and rl_gracetime, these params
# are used to configure rate limiting.
#rl_decay=1800

# Configures the number of failed attempts before increasing the difficulty level
#rl_threshold=1

# Sets the number of additional seconds allowed - beyond the max solution time
# fixed for a certain difficulty - before a rate-limiting puzzle expires.
#rl_gracetime=10

# Sets the path to the long-term signature private key. You can generate one by
# running 'oracle init'. This will also create a public key and its Base64
# encoded variant, which should be published to all potential users so that they
# can use your oracle in a threshold setup.
#ltsigkey="oracle.key"
```

```
[server]
# Determines on what address the server is listening. The default is localhost
# -- you might want to change that to whatever IP address you want the
# oracle to be listening on.
#address="127.0.0.1"

# Sets the port the server is listening on. The default is 2355. Another
# recommended port value is 443, which is allowed by most firewalls, while
# 2355 is not. You should set this to 443 if possible, as it will enable
# you to have always access to the oracle when you are on the go, since
# other ports might very well be firewalled, but port 443 is very rarely blocked.
#port=2355

# Required. Have no defaults, and must be set to point at a traditional TLS
# certificate and secret key file. Set ssl_key to the file domain.key and
# ssl_cert to the file signed_chain.crt both from the previous section
# "Getting a TLS Certificate Using Let's Encrypt". It is not recommended to
# use self-signed certs, but CA-signed certs that are recognized widely by
# browsers and other TLS clients when possible.
ssl_key="domain.key"
ssl_cert="signed_chain.crt"

# Sets the TCP connection timeout. Increase for slow networks, with the caveat
# that this might lead to easier resource exhaustion, by blocking all workers.
#timeout=3

# Sets the maximum number of requests handled in parallel. The timeout config
# variable makes sure that all handlers are recycled in predictable time.
#max_kids=5

# The data directory where all the device "secrets" are stored. This defaults
# to `data/` in the current directory. Backup this directory regularly and
# securely, since the loss of this directory means users lose access to their
# passwords.
#datadir="/var/lib/sphinx"

# Enables logging to standard output.
#verbose=false

# Specifies the number of seconds after which a rate-limit level decays to an
# easier difficulty. Together with rl_threshold and rl_gracetime, these params
# are used to configure rate limiting.
#rl_decay=1800

# Configures the number of failed attempts before increasing the difficulty level
#rl_threshold=1

# Sets the number of additional seconds allowed - beyond the max solution time
# fixed for a certain difficulty - before a rate-limiting puzzle expires.
#rl_gracetime=10

# Sets the path to the long-term signature private key. You can generate one by
# running 'oracle init'. This will also create a public key and its Base64
# encoded variant, which should be published to all potential users so that they
# can use your oracle in a threshold setup.
#ltsigkey="oracle.key"
```

Apart from the `address`, `port`, `ssl_key` and `ssl_cert`, you need
not touch the rest of the config.

## Initializing the Oracle

Given a configuration, the oracle can generate its own long-term signature key by running:

```
oracle init
```

This stores the private key at the location specified by `ltsigkey` and
outputs the corresponding public key at the same location, with a `.pub`
extension. The public key is also displayed as a Base64-encoded string on
standard output.

## Running the Oracle

When the configuration is complete, simply run `oracle` to start the server in the foreground. The oracle does not take any parameters.

## Deployment and Security Considerations

Use whatever your distro provides to daemonize and log the output of
servers to have the oracle automatically started at reboot.

The `max_kids` and `timeout` settings can be used to control how many requests are served in parallel and how long each request can run. Without careful tuning, an attacker could launch a denial-of-service attack by keeping all `max_kids` connections busy.

Since the oracle only knows about failed authorizations for management operations (not incorrect master passwords for `get` requests), brute-force attempts can only be mitigated via rate limiting. Adjusting `rl_*` parameters allows you to make puzzles more difficult. On devices with less than 1GB RAM, you can increase the difficulty enough that they cannot solve the puzzles.

Rate limiting in general should not be noticeable, unless dozens of `get` requests are made to the same record. At the highest difficulty level, solving should take around 20–40 seconds, depending on CPU performance.

Congratulations! Now invite your friends (and enemies!) to use your
instance :)

You could also set up the whole thing as a Tor
hidden service, so you can protect the privacy of your users even
better. How to do so is left as an exercise to the dear reader.
