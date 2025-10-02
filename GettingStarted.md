# Getting Started with SPHINX

So you want to start using SPHINX for handling your passwords. Great, welcome!

SPHINX is a cryptographic password storage protocol that uses client-server architecture. Unlike traditional password managers that encrypt a database file, SPHINX servers store only cryptographic blobs that are mathematically useless without your master password. Even if compromised, your actual passwords remain secure with information-theoretic security guarantees.

**Note:** To use SPHINX, your client needs to be able to connect to the oracle.

## Quick Start

### 1. Install SPHINX Client

**Debian/Ubuntu and derivatives:**

```bash
sudo apt install pwdsphinx
# Optional: for browser extensions and X11 integration  
sudo apt install pinentry-gtk2 xdotool xinput
```

**Other systems:** See the **[installation guide](https://sphinx.pm/client_install.html)** for building from source and dependencies.

### 2. Initialize Your Client

```bash
sphinx init
```

This creates your master key (`~/.sphinx/masterkey`) - **BACK THIS UP!** It also automatically sets up browser extension hosts if `~/.mozilla` or `~/.config/chromium` directories are found.

For Android devices, export your config using `sphinx qr key`. This creates a QR code that can be read by the [androsphinx](https://github.com/dnet/androsphinx) Android app, allowing the app to use the same configuration as you have set up above.

### 3. Configure a Server

Edit `~/.sphinxrc`:

```ini
[servers]
[server.server-name]
address=your.sphinx-server.tld
port=443
```

**Need a server?**

- **Use existing server:** See **[public servers](https://sphinx.pm/servers.html)**
- **Host your own:** Follow the **[server setup guide](https://sphinx.pm/server_install.html)**

### 4. Test Your Setup

```bash
# Create a test password
echo -n "testpassword" | sphinx create testuser example.com

# Retrieve it (use getpwd for security)
getpwd | sphinx get testuser example.com

# Clean up
sphinx delete testuser example.com

# Verify it's gone
echo -n "testpassword" | sphinx get testuser example.com  # Should error
```

## What's Next?

- **[Complete Usage Guide](man/sphinx.md)**: All operations and options
- **[Browser Extensions](#browser-extensions)**: Seamless web login  
- **[X11 Integration](https://sphinx.pm/x11-integration.html)**: Desktop automation
- **[Server Hosting](https://sphinx.pm/server_install.html)**: Run your own oracle

## Browser Extensions

SPHINX provides browser extensions for Firefox and Chrome/Chromium
that enable seamless password filling on websites.

websphinx consists of two parts: the frontend (which is the add-on to install from
the browser extension store) and the backend (which handles everything).
The backend is actually a native messaging host that communicates with the browser extension. 
The native messaging host is auto-configured by `sphinx init`.

### Prerequisites

Install pinentry for secure password input:

```bash
# Choose one appropriate for your desktop environment:
sudo apt install pinentry-gtk2      # GTK/GNOME
sudo apt install pinentry-qt        # KDE/Qt  
sudo apt install pinentry-gnome3    # Modern GNOME
sudo apt-get install pinentry-fltk      # Lightweight option
```

### Firefox Extension

1. **Install from [Firefox Add-ons Store](https://github.com/stef/pwdsphinx/releases/tag/v2.0.0)**
2. **Configure pinentry** (if not using default `/usr/bin/pinentry`):
   
   Add to `~/.sphinxrc`:
   
   ```ini
   [websphinx]
   pinentry=/usr/bin/pinentry-gtk-2
   ```

3. **Restart Firefox** and enjoy!

### Chrome/Chromium Extension  

1. **Download** from [websphinx-chrom repository](https://github.com/stef/websphinx-chrom)
2. **Install in Developer Mode:**
   - Open `chrome://extensions`
   - Enable "Developer mode"
   - Click "Load unpacked extension"
   - Select the downloaded directory
3. **Configure pinentry** (same as Firefox above)
4. **Restart browser** and enjoy!
