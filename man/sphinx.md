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

`sphinx` healthcheck

`sphinx` qr [\<svg>] [\<key>]


In general, if any operation requires a master (input) password, it is expected on standard input, and any resulting account (output) password is printed to standard output. In the examples we use `echo` but it is recommended to use `getpwd(1)` or similar tools to query and pass the input password.

# DESCRIPTION

SPHINX – password Store that Perfectly Hides from Itself (No Xaggeration) – is an information-theoretically secure cryptographic password storage protocol with strong security guarantees. The protocol is described in the 2015 paper "Device-Enhanced Password Protocols with Optimal Online-Offline Protection" by Jarecki, Krawczyk, Shirvanian, and Saxena (https://ia.cr/2015/1099).

# OPERATIONS

`sphinx` is the command-line client for the SPHINX protocol. It provides access to all operations over the lifecycle of a password: `init`, `create`, `get`, `change`, `undo`, `commit`, `delete`, and `list`. All operations require a username and a site that the password belongs to, even if they're just empty strings. Additionally, it provides operations that make these features more user-friendly: listing of users associated with a host and export of the configuration using a QR code.



`sphinx` not only handles passwords, but also handles Time-based One-Time Password (TOTP) Two-Factor Authentication (2FA) and [age keys](https://age-encryption.org). Additionally, if installed, `sphinx` also provides access to [OPAQUE-Store](https://github.com/stef/opaque-store), a simple tool that allows one to store secrets that need encrypted storage (like keys, phrases, or other data).

## INITIALIZING A CLIENT

```
sphinx init
```

This creates a new masterkey for the client, which is used to address records on the SPHINX server and authorize management operations on those records.

You **SHOULD** back up and encrypt this masterkey.

If you want to use SPHINX on a different device, you want to copy this masterkey there as well. For copying this key (and other settings) to the Android client, [androsphinx](https://github.com/dnet/androsphinx), see the `qr` operation below.

This `init` operation also creates a fixed healthcheck record on the server(s), as described in the `HEALTHCHECK` section below.

## CREATE PASSWORD

To create a new password for a site, provide your **master password** via standard input to the client, along with the required parameters. For example:

```
echo -n 'my input password' | sphinx create username example.com ulsd 0 ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
```

The parameters are:

- **Master password on standard input**: Unlike traditional password managers that use a single master password for the entire database, you can use different input passwords for different username/site combinations.
- `create`: Specifies the operation type.
- `username`: Your username for the site.
- `example.com`: The target site.
- **Password constraints**: Rules for generating the password. See sections `PASSWORD RULES` and `PREDETERMINED PASSWORDS` for more info.

If the command runs successfully, the resulting new high-entropy output password, generated according to the given rules, is printed to the console.

## GET PASSWORD

To retrieve a stored password from the SPHINX oracle, run:

```
echo -n 'my master password' | sphinx get username example.com
```

You provide your **master password** via standard input, followed by:

- `get`:  Specifies the operation.
- `username`:  Your username.
- `example.com`:  The site.

The corresponding password is printed to standard output.

## CHANGE PASSWORD

If you need to change a password (whether required by the site or voluntarily), you can do so without changing your master password — although you may change both if desired. For example:

```
echo -en 'my master password\nnew masterpassword' | sphinx change username example.com 'ulsd' 0 ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
```

The parameters are:

- On standard input, provide your **current master password**, followed by a newline, then your **new master password**. The new master password can be identical to the old one if you only want to update the site password.
- `change`: Specifies the operation.
- `username`: Your username.
- `example.com`: The site.
- **Password generation rules**: Same format as when creating the original password. Adjust these if the site now requires different constraints (see `PASSWORD RULES` and `PREDETERMINED PASSWORDS`).

The newly generated password will be printed to standard output.

**IMPORTANT:** This command *only generates* the new password, but it does not activate it. The `get` command will still return your old password until you run a `commit` operation to make the change effective. See the next section for details.

## COMMITTING A CHANGED PASSWORD

After changing a password, the `get` operation will still return the old password. To start using the new password, you must commit the change by running:

```
echo -n 'my master password' | sphinx commit username example.com
```

Depending on your `rwd_keys` configuration (explained in the `SECURITY CONSIDERATIONS` section below), you may need to provide your input password on standard input for this operation.

If the operation is successful, there will be no output. If an error occurs, an error message will be displayed and the command will exit with a non-zero status code.

## UNDOING A PASSWORD COMMIT

If you need to revert to the old password after committing a new one, run:

```
echo -n 'my master password' | sphinx undo username example.com
```

Depending on your `rwd_keys` configuration, you may need to provide your master password on standard input for this operation.

If successful, there will be no output. Otherwise, an error message and a non-zero exit code will indicate a problem.

## DELETING PASSWORDS

To delete a password, use the following command:

```
echo -n "my master password" | sphinx delete username example.com
```

Here:

- `delete` specifies the operation.
- `username` is your account name.
- `example.com` is the target site.

If the operation succeeds, there will be no output. If it fails, you will see an error message and a non-zero exit code. Depending on your `rwd_keys` configuration, you may need to provide your master password via standard input.

## QR CODE CONFIG

If you want to use your phone with the same SPHINX server, you can export your configuration to the phone using a QR code.

```
sphinx qr
```

This displays a QR code containing only public information, such as the server host, port, and whether `rwd_keys` is enabled. This is useful for sharing your setup with trusted friends or family.

To connect your own phone to the setup used with `pwdsphinx`, include your client secret in the QR code:

```
sphinx qr key
```

This QR code contains sensitive information, so keep it private and ensure no cameras can capture it while it's displayed.

To display the QR code as an SVG instead of text, append the `svg` keyword to the `sphinx qr` command:

```
sphinx qr svg
```

## HEALTHCHECK

If you have run the `sphinx init` command, it has created a fixed healthcheck record. You can verify your setup by running:

```
sphinx healthcheck
```

This checks connectivity to the server without affecting rate limits. Alternatively, you can test with a `get` operation:

```
echo -n 'all ok?' |  env/bin/sphinx get healthcheck "sphinx servers"
```

This should output *"everything works fine"*. The difference is that `healthcheck` only fetches rate-limiting challenges and then stops, while `get` will count against your rate limit if used too frequently.

## PASSWORD RULES

When creating or changing passwords, you can specify rules limiting the size and characters allowed in the output password.

The letters `u`, `l`, `s`, and `d` represent the following character classes:

- `u`: Upper-case letters
- `l`: Lower-case letters
- `s`: Symbols
- `d`: Digits

The `s` shortcut includes all supported symbols. If you are limited by the server to specific symbols, you can explicitly specify them. Supported symbols (note the leading space character) are:

```
 !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
```

When using these symbols on the command line, be sure to escape quotes and possibly the backslash character. In the `create username` example above, symbols are correctly escaped for copy/paste.

For examples, see the sections **CREATE PASSWORD** and **CHANGE PASSWORD**.

### DEFAULT RULES

If you do not specify password rules, they will default to `ulsd` with the maximum possible length of 77 characters. This means passwords will use all four character classes, providing 507 bits of entropy. This is far more than necessary for most use cases.

### RECOMMENDED OUTPUT PASSWORD LENGTH

When using the `ulsd` character classes, it is recommended to limit the output password length to a maximum of 12 characters. This is especially useful if you ever need to type the password on a TV remote or in other stressful situations. A 12-character password with full entropy using all printable ASCII characters offers almost 80 bits of entropy, making it computationally impossible to brute force with current password-cracking hardware. For comparison, a 15-character password offers nearly 99 bits of entropy.

## PREDETERMINED OUTPUT PASSWORDS

If you cannot use random passwords for your account, or if you need to store a fixed "password" such as a PIN code or a shared passphrase, you can set a predetermined password (up to 77 characters). The SPHINX client will generate it for you. For example, the command below (which also works for the `change` operation) sets a fixed password:

```
echo -n 'my master password' | sphinx create username example.com "correct_battery-horse#staple"
```

In this case, you cannot specify character classes, size, or symbols. These values will be inferred from the predetermined password itself.

## Backward compatibility with v1 SPHINX servers/records

If you still have SPHINX records on the server created with v1 and want to use them, you must specify this server in the client section as you did in v1. If no v2 record is found during a `get` operation, SPHINX will automatically attempt to retrieve a v1-style record. If a v1 record is found, a new v2 record will be created automatically, so there's no need to manually check for v1 records in this case.

If you are not using other v1-only clients (like androsphinx), upgraded v1 records can be automatically deleted after a successful migration to v2. To enable this, set `delete_upgraded` to `true` in the `[client]` section of your SPHINX configuration. This helps keep the server database clean and makes it easy to track how many v1 records still remain.

## OUTPUT PLUGINS (TOTP & AGE)

SPHINX can also "store" TOTP secrets and age secret keys. When storing such a secret, SPHINX will automatically handle it appropriately (e.g., outputting the TOTP verification code instead of the secret). To do this, prefix your username with `otp://` for TOTP support, or `age://` for age key support. For age keys, the query will return a correctly formatted private key.

Currently, the following converters are supported:

### TOTP

Import a TOTP secret

```sh
% getpwd | sphinx create otp://username example.com ABCDEF1234567890
```

Get a TOTP PIN:

```
% getpwd | sphinx get otp://username example.com
```

### minisign

Create a new key and store the public key at `/tmp/minisig.pub`:

```sh
% getpwd \
    | sphinx create minisig://user example.com >/tmp/minisig.pub
```

`Create` and `Change` SPHINX operations automatically return a public key.

Sign a file `filetosign`:

```sh
% getpwd \
    | sphinx get minisig://user example.com \
    | pipe2tmpfile minisign -S -s @@keyfile@@ -m filetosign
```

The `Get` SPHINX operation returns a private key.

### Age

Generate an age key and store the public key:

```sh
% getpwd \
    | sphinx create age://user example.com >/tmp/age.pub
```

`Create` and `Change` SPHINX operations automatically return a public key.

Decrypt a file using an age key from SPHINX:

```sh
% getpwd \
    | sphinx get age://user localhost \
    | pipe2tmpfile age --decrypt -i @@keyfile@@ encryptedfile
```

The `Get` SPHINX operation returns a private key.

### SSH-ED25519

Create a key and save the public key:

```sh
% getpwd \
   | sphinx create ssh-ed25519://test asdf >pubkey
```

`Create` and `Change` SPHINX operations automatically return a public key.

Sign a file:

```sh
% getpwd \
   | sphinx get ssh-ed25519://test asdf \
   | pipe2tmpfile ssh-keygen -Y sign -n file -f @@keyfile@@ content.txt > content.txt.sig
```

The `Get` SPHINX operation returns a private key.

Verify a file with a public key:

```sh
% ssh-keygen -Y check-novalidate -n file -f /tmp/ssh-ed.pubkey -s /tmp/content.txt.sig </tmp/content.txt
```

## OPAQUE-Store INTEGRATION

If you have OPAQUE-Store ([see GitHub](https://github.com/stef/opaque-store/)) installed and configured correctly (see `opaque-stored.cfg(5)`), you gain access to additional commands that let you store encrypted blobs of data. These commands will be available only if OPAQUE-Store is properly set up:

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

In all OPAQUE-Store commands, a SPHINX `get` operation runs first. This generates the password used with OPAQUE, ensuring that the OPAQUE password is extremely strong and nearly impossible to brute-force without going through SPHINX. However, online brute-force attempts via SPHINX are still possible. OPAQUE can detect invalid passwords and lock records after a configured number of failed attempts. This lock does not apply to the operator of an OPAQUE server, who could bypass it.

### A WARNING: Don't let one entity control enough of your SPHINX and OPAQUE-Store servers

Every OPAQUE-Store operation requires a password via standard input. This password is run through SPHINX, and the output password is then used in the OPAQUE protocol as the input password. This means that if both SPHINX and OPAQUE-Store are hosted on the same server or controlled by the same third party, they could potentially perform an offline brute-force attack against your SPHINX master password. If you use a threshold setup where different entities control the servers, you remain secure as long as no single entity controls enough servers to meet the threshold.

### OPAQUE-Store CLI Parameters

#### KeyId

Every OPAQUE-Store integration command needs a `keyid` parameter, which references your stored record. The client uses the `id_salt` configuration value together with the OPAQUE-Store server's name to hash the `keyid` into a record ID. If you lose or change either `id_salt` or the server name, your record IDs will change, and your data will become inaccessible. Back up your configuration file to avoid this. While `id_salt` does not need to be secret, keeping it private adds an extra layer of security.

#### Forced operations

In threshold setups, certain commands (`replace`, `edit`, `changepwd`, and `erase`) require that all servers participate successfully in the operation. This is to avoid situations where some servers become out of sync (corrupted) from the others. If you are certain it's safe, you can add the `force` flag to allow the operation to succeed with only the minimum number of servers specified by your `threshold` setting.

### Store an encrypted blob

```sh
getpwd | sphinx store <keyid> file-to-store
```

Stores the specified `file-to-store` in encrypted form on the OPAQUE-Store server, using a password derived from SPHINX. **Note**: This command also outputs a recovery token, which you should keep safe in case the record is ever locked.

### Retrieve an encrypted OPAQUE-Store blob

```sh
getpwd | sphinx read <keyid>
```

Retrieves the record stored at `keyid` and outputs it to standard output.

### Overwrite an encrypted OPAQUE-Store blob

```sh
getpwd | sphinx replace [force] <keyid> file-to-store
```

Replaces the record stored at `keyid` with an encrypted version of `file-to-store`. This command only works if a record already exists at `keyid`. By default, all servers must participate successfully. If some are unavailable, you can use `force` to proceed as long as the threshold is met — but unavailable servers will become out of sync (corrupted) from this point on.

### Edit an OPAQUE-Store blob

```sh
getpwd | sphinx edit [force] <keyid>
```

This operation fetches the file stored at `keyid`, opens it in your default editor (specified by the `EDITOR` environment variable), and stores the saved changes back at the same `keyid`, overwriting the original.

### Change your password on an OPAQUE-Store blob

```sh
getpwd | sphinx changepwd [force] <keyid>
```

This operation rotates all passwords and keys for the record at `keyid`. Even if your own password (supplied to `getpwd`) stays the same, SPHINX will generate a new key, which in turn produces a new OPAQUE password. This results in a completely new encryption key for your file, and the file is re-encrypted with it.

### Delete a stored OPAQUE-Store blob

```sh
getpwd | sphinx erase [force] <keyid>
```

Deletes the record stored at `keyid`.

### Get a recovery token

```sh
getpwd | sphinx recovery-tokens <keyid>
```

This operation generates and returns an additional recovery token, provided the record is not currently locked.

### Unlock a locked OPAQUE-Store blob

```sh
getpwd | sphinx unlock <keyid> <recovery-token>
```

This operation unlocks a record that has been locked by the servers (for example, after repeated failed login attempts or if you forgot your master password). It requires a valid recovery token. Once unlocked, the record is automatically retrieved — unless the wrong password is provided again.

# SPHINX CONFIGURATION

The client can be configured by any of the following files (read in this order):

- `/etc/sphinx/config`
- `~/.sphinxrc`
- `~/.config/sphinx/config`
- `./sphinx.cfg`

Later files override earlier ones, allowing global settings to be overridden by per-user and per-directory settings.

## Client Settings (`[client]` section)

- **`datadir`** (default: `~/.sphinx`): Specifies the directory where client parameters are stored. Particularly, it contains a masterkey which is used to derive secrets. If missing, it is generated by the `init` command. You **SHOULD** back up and encrypt this master key.

- **`rwd_keys`**: Toggles whether the master password is required for authentication of management operations. The oracle is oblivious to this setting, this is purely a client-side toggle. In theory, it is possible to have different settings for different "records" on the oracle.

- **`validate_password`**: Stores a 5-bit check digit on the server that helps to detect most master password typos, while slightly reducing security.

- **`userlist`** (default: True): When disabled, it prevents the server from correlating all usernames belonging to the same SPHINX user for the same host. If disabled, the user must remember which username is used for each host.

- **`address`** / **`port`**: These variables are only used for backward compatibility with old v1 servers. If no record is found with a v2 `get` operation, SPHINX will then attempt a v1-style `get` request and see if the record is available from "old times". If a v1 record is found, a new v2-style record is created. A v1 `get` request for this particular record is not needed anymore.

- **`delete_upgraded`**: Enables automatic deletion of v1 records after upgrading to v2. This setting is recommended unless using v1-only clients like androsphinx. It enables server operators to see if their users are finally completely v2, so that they can disable v1 support.

- **`threshold`**: Specifies the number of servers required for SPHINX operations. If the `[servers]` section contains more than two entries, this value must be greater than 1 and less than the number of servers listed in the `[servers]` section: `1 < threshold < len(servers)`.

## Server Settings (`[servers]` section)

The `[servers]` section contains one subsection per server. For example:

```
[servers]
[servers.zero]
host="localhost"
port=10000
ltsigkey = "32byteBase64EncodedValue=="
```

- **Section format:** `[servers.<name>]`. The `name` can be freely chosen and can be a public value. It is **important** to never change it, as long as you want to access your passwords on this server. This name value is used together with other values to create unique record IDs. If you change the `name`, the record IDs change, and you will not be able to access your old records.

- **`host`** and **`port`**: should match what you set (or its admin publishes) in the `oracle(1)` server.

- **`ltsigkey`**: This is the server's long-term signing key for threshold operations. This should be a base64-encoded value; however, you can also store the raw binary key in a file and use the `ltsigkey_path` option instead. This key is only needed for threshold setup, and is not required in single-server mode.

See `oracle(1)` for more configuration parameters.

# SECURITY CONSIDERATIONS

- You **SHOULD** back up and encrypt your masterkey. You can do this using the `qr key` operation, recording other important details as well. Backing up `webauthn_data_dir` from the `[websphinx]` section is also recommended if using the web extension and WebAuthn.

- **`rwd_keys`** setting:
  - If **False**: protects against offline master password brute-force attacks (a security guarantee of SPHINX).
  - If **True**: prevents denial-of-service attacks where an attacker could change/delete records for known (host, username) pairs if they have the masterkey, but removes the offline brute-force protection.
  
  This is a trade-off between account password availability and master password confidentiality.

- **`validate_password`**: Stores a 5-bit check digit on the server that helps to detect most master password typos. If enabled, this setting decreases security slightly but is generally safe to enable.

- **`userlist`** (default: enabled): This configuration setting allows a server operator to correlate records belonging to the same SPHINX user for the same online service. If multiple accounts on the same service are managed by the same SPHINX server, the server operator can detect when a userlist record is updated and which SPHINX record belongs to this operation. This leaks some information that can be used by an adversarial server operator to correlate records.

## Password Entry Example

In this documentation, `echo` is used only for demonstration. For real usage, use `getpwd(1)` from the `contrib` directory if you are not interested in customizing or consider something like:

```
echo GETPIN | pinentry | grep '^D' | cut -c3- | sphinx create username example.com ulsd 0
```

Using `pinentry`, you can enable double password input, and password quality checks. It's quite versatile.

# REPORTING BUGS

https://github.com/stef/pwdsphinx/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2024 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later https://gnu.org/licenses/gpl.html.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

https://www.ctrlc.hu/~stef/blog/posts/sphinx.html

https://www.ctrlc.hu/~stef/blog/posts/oprf.html

https://github.com/stef/opaque-store/

`oracle(1)`, `getpwd(1)`, `opaquestore(1)`
