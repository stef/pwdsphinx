# SPHINX X11 Integration Tools

This directory contains tools that can be used on their own, or in concert to interact with pwdsphinx on X11 desktops. SPHINX is not your average legacy consumer-grade password manager - its CLI is powerful, but its X11 integration is what makes it truly efficient for daily use on Linux desktops and laptops.

The tools are designed with security in mind, ensuring that passwords never appear in process lists, command history, or the clipboard where malware could intercept them. Instead, they use secure input methods and direct keyboard injection via `xdotool` and `xinput` to automate password entry and multi-factor authentication seamlessly.

These tools build on SPHINX's core operations (`create`, `get`, `change`, `commit`, `undo`, `list`, `delete`) and alternate converters (`otp://`, `age://`, `minisig://`, `ssh-ed25519://`, `raw://`) to provide a complete desktop integration experience.

For detailed technical documentation of the scripting language and advanced usage, see the [X11 integration documentation](https://sphinx.pm/x11-integration.html). For core SPHINX CLI operations used by these tools, see [sphinx(1)](../man/sphinx.md).

## Tools Reference

### getpwd (depends on pinentry)

This is a simple script that uses `pinentry` from the GnuPG project to securely query a password and write it to standard output. This should be safer than echoing a password into pwdsphinx, since your password will not show up in your process list nor your command line history.

See [`getpwd(1)`](../man/getpwd.md) for usage details.

### exec-on-click (depends on xinput)

This is a simple shell script that depends on `xinput`, which waits for a left mouse click and then executes the specified command.

See [`exec-on-click(1)`](../man/exec-on-click.md) for usage details.

### type-pwd (depends on xdotool, exec-on-click and getpwd)

This script combines `getpwd`, `exec-on-click`, and the pwdsphinx client to create a secure password entry workflow. It prompts for your master password, waits for you to click on a password field, then types the password as keystrokes. This approach ensures passwords never appear in the clipboard where malware could intercept them.

See [`type-pwd(1)`](../man/type-pwd.md) for usage details.

### dmenu-sphinx (depends on dmenu, type-pwd)

This tool provides an interactive interface for retrieving SPHINX passwords using `dmenu` to present hostname and username selection menus. It builds on `type-pwd` for secure password entry with hostname history caching.

See [`dmenu-sphinx(1)`](../man/dmenu-sphinx.md) for usage details.

### pipe2tmpfile

This tool bridges commands that output to stdout with commands requiring file input. It reads data from stdin, writes it to a secure temporary file, executes a command with `@@keyfile@@` replaced by the temp file path, then automatically cleans up.

See [`pipe2tmpfile(1)`](../man/pipe2tmpfile.md) for usage details and security considerations.

### sphinx-x11

This script language interpreter integrates the SPHINX CLI with X11 using a domain-specific language (DSL) for automating password entry and multi-factor authentication. It includes example scripts for various login workflows including 2FA support.

See [`sphinx-x11(1)`](../man/sphinx-x11.md) for script language vocabulary, examples, and usage details.

## Customization and Usage

You can create your own scripts for different sites and workflows using the scripting language, and bind them to keyboard shortcuts for even faster access. This approach keeps your passwords out of the clipboard and leverages X11 automation for secure, efficient logins.

If you prefer browser integration, SPHINX also [provides web extensions for Firefox and Chrome-based browsers](../GettingStarted.md#setting-up-browser-extensions). However, always be cautious with browser extensions and review their security implications.

## See Also

**Manual Pages:** [`getpwd(1)`](../man/getpwd.md), [`exec-on-click(1)`](../man/exec-on-click.md), [`type-pwd(1)`](../man/type-pwd.md), [`dmenu-sphinx(1)`](../man/dmenu-sphinx.md), [`pipe2tmpfile(1)`](../man/pipe2tmpfile.md), [`sphinx-x11(1)`](../man/sphinx-x11.md), [`websphinx(1)`](../man/websphinx.md)

**[Technical Reference](https://sphinx.pm/x11-integration.html):** Complete scripting language vocabulary, advanced usage patterns, and detailed script analysis

**[OPAQUE-Store Integration](https://sphinx.pm/opaque-store_integration.html):** Encrypted storage for keys and secrets beyond password generation
