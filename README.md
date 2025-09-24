<!--
SPDX-FileCopyrightText: 2018, Marsiske Stefan

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# SPHINX: A Password **S**tore that **P**erfectly **H**ides from **I**tself (**N**o **X**aggeration)

SPHINX is a cryptographic password storage protocol that provides information-theoretic security. pwdsphinx is a Python wrapper around [liboprf](https://github.com/stef/liboprf) - a cryptographic password storage
as described in https://eprint.iacr.org/2015/1099.

Unlike traditional password managers, SPHINX only stores random numbers unrelated to your actual passwords, ensuring the server learns nothing about them.

**Key Features:**

- 🔒 **Information-theoretic security**: Mathematically proven protection
- 🌐 **Zero-trust architecture**: Server knows nothing about your passwords  
- 🚫 **Offline bruteforce resistance**: Your passwords are safe even if the server is compromised
- 🏠 **Self-hostable**: Run your own server or use someone else's
- 📱 **Cross-platform**: CLI, browser extensions, Android app, and X11 integration
- 🔑 **Password generation**: Creates strong passwords according to site requirements

## Also on Radicle

To clone this repo on [Radicle](https://radicle.xyz):

```bash
rad clone rad:z3rjK2hk7ckb1thexdsuyaM7e4FwS
```

## Dependencies

### Required Dependencies

- **[liboprf](https://github.com/stef/liboprf)**: An Oblivious Pseudo-Random Function (OPRF) is a cryptographic protocol where a client can evaluate a pseudo-random function on their input using a key held by a server, without the server learning the client's input or the function's output. liboprf implements OPRFs, which is used to enables SPHINX's zero-knowledge password storage.
- **[libequihash](https://github.com/stef/equihash/)**: This provides rate limiting proof-of-work with fast verification
- **pysodium** and **pyoprf**: Python cryptographic bindings. Both can be installed using either
your OS package manager or pip.

### Optional Dependencies

**For browser extensions:**
If you also want to use the websphinx browser extension, you
also need to install an X11 variant of pinentry from the GnuPG project.

```bash
# Install any one of these, using the equivalent of `apt-get` on your operating system:
apt-get install pinentry-qt        # For KDE/Qt environments
apt-get install pinentry-gtk2      # For older GNOME/GTK environments
apt-get install pinentry-gnome3    # For modern GNOME environments
apt-get install pinentry-fltk      # Lightweight option
```

**For X11 integration:**

- **xdotool**: Keyboard/mouse automation
- **xinput**: Input device control  
- **dmenu**: Interactive menus

**For extended storage:**
If you want to store other "secrets" that are longer than just 77 chars, you
can install OPAQUE-Store:

- **[opaque-store](https://github.com/stef/opaque-store/)**:  Encrypted file storage: `pip3 install opaquestore`
- **[OPAQUE-Store](https://github.com/stef/libopaque)**:  OPAQUE protocol implementation, a dependency for OPAQUE-Store above.

## Installation

```bash
pip3 install pwdsphinx
```

On Debian-based systems, you can also do:

```bash
sudo apt install pwdsphinx
```

## Architecture

SPHINX uses a client-server architecture where:

### Server (Oracle)

The server stores only cryptographic blobs that are useless without your master password. Even if compromised, your actual passwords remain secure.

**Host your own server:** See [`oracle(1)`](man/oracle.md) or the [Server Installation Guide](GettingStarted.md#hosting-your-own-oracle) for how to configure your server.

### Client

The client combines your master password with the server's response to regenerate your actual passwords deterministically.

**Supported platforms:**

- **Command Line:** Full-featured CLI client (see [`sphinx(1)`](man/sphinx.md) for how to configure a client)
- **Browser:** [Firefox and Chromium extensions](./GettingStarted.md#setting-up-browser-extensions) with native messaging
- **Desktop:** [X11 integration scripts](./contrib/README.md) for form filling
- **Mobile:** Android app ([androsphinx](https://github.com/dnet/androsphinx))

## Usage

SPHINX provides a complete lifecycle for password management:

### Core Operations

- **`create`**: Generate new password for a site
- **`get`**: Retrieve existing password  
- **`change`**: Update password (two-phase commit)
- **`commit`**: Activate changed password
- **`undo`**: Revert to previous password
- **`delete`**: Remove password record
- **`list`**: Show usernames for a site

### Management Operations  

- **`init`**: Initialize client with new master key. It also sets up browser extensions if `~/.mozilla` or `~/.config/chromium` directories are found.
- **`healthcheck`**: Test server connectivity
- **`qr`**: Export configuration as QR code

See [`sphinx(1)`](man/sphinx.md) for detailed command syntax and examples.

## OPAQUE-Store Client Integration

If you have OPAQUE-Store installed and configured correctly, you get a number of
additional operations, which allow you to store traditionally encrypted blobs
of information. For a gentle introduction on how this works using the OPAQUE protocol, have a look at this post: https://www.ctrlc.hu/~stef/blog/posts/How_to_recover_static_secrets_using_OPAQUE.html

The following operations will be available if OPAQUE-Store is setup correctly:

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

See the [OPAQUE-Store X11 integration](https://sphinx.pm/opaque-store_integration.html) documentation for more details on these operations and how the integration
works with SPHINX.  

## Browser Integration

There is WebSphinx, our browser extension that provides
seamless password filling. See the [browser extension instructions](./GettingStarted.md#Setting-Up-Browser-Extensions) on how to set it up
on Firefox and Chrome/Chromium browsers

## X11 Desktop Integration

SPHINX includes shell scripts for X11 desktop integration using `dmenu`, `xdotool`, `xinput`, and `pinentry`.

The main script [`dmenu-sphinx.sh`](./contrib/dmenu-sphinx) provides interactive password filling with a dmenu interface. It stores hostname history in `~/.sphinx-hosts` (link to `/dev/null` if you consider this sensitive).

The integration enables automatic form filling in X11 applications through keyboard automation for password entry. It works with pinentry for secure password input.

See [`contrib/README.md`](contrib/README.md) for setup examples and script combinations.

## More documentation

### For Users

- **[Getting Started Guide](GettingStarted.md)**: Complete setup and usage tutorial
- **[Manual Pages](man/)**: Detailed command reference
  - [`sphinx(1)`](man/sphinx.md): Main client commands
  - [`oracle(1)`](man/oracle.md): Server configuration and management  
  - [`getpwd(1)`](man/getpwd.md): Secure password input utility

### For Developers & Advanced Users

- **[X11 Integration](https://sphinx.pm/x11-integration.html)**: Desktop automation scripts
- **[OPAQUE-Store Integration](https://sphinx.pm/opaque-store_integration.html)**: Encrypted file storage
- **[Contributing Scripts](contrib/README.md)**: Helper utilities and examples

## Credits

This project was funded through the NGI0 PET Fund, a fund established
by NLnet with financial support from the European Commission's Next
Generation Internet programme, under the aegis of DG Communications
Networks, Content and Technology under grant agreement No 825310.

This project was funded through the e-Commons Fund, a fund established by NLnet
with financial support from the Netherlands Ministry of the Interior and
Kingdom Relations.

Everlasting gratuity to asciimoo, dnet, jonathan and hugo for their
contributions, patience, and support.
