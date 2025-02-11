all: sphinx.1 oracle.1 bin2pass.1 websphinx.1 getpwd.1 exec-on-click.1 type-pwd.1 dmenu-sphinx.1 sphinx-x11.1 sphage.1 \
	otp.sphinx.1 pass.sphinx.1 user-pass-otp.sphinx.1 user-pass.sphinx.1 getacc-user-pass.sphinx.1 pipe2tmpfile.1

html: sphinx.html oracle.html bin2pass.html websphinx.html getpwd.html exec-on-click.html type-pwd.html dmenu-sphinx.html sphinx-x11.html sphage.html \
	otp.sphinx.html pass.sphinx.html user-pass-otp.sphinx.html user-pass.sphinx.html getacc-user-pass.sphinx.html pipe2tmpfile.html
 
install: $(PREFIX)/share/man/man1/sphinx.1 $(PREFIX)/share/man/man1/oracle.1 $(PREFIX)/share/man/man1/bin2pass.1 \
	$(PREFIX)/share/man/man1/getpwd.1 $(PREFIX)/share/man/man1/exec-on-click.1 $(PREFIX)/share/man/man1/type-pwd.1 \
	$(PREFIX)/share/man/man1/dmenu-sphinx.1 $(PREFIX)/share/man/man1/sphinx-x11.1 $(PREFIX)/share/man/man1/sphage.1 \
	$(PREFIX)/share/man/man1/websphinx.1 $(PREFIX)/share/man/man1/otp.sphinx.1 $(PREFIX)/share/man/man1/pass.sphinx.1 \
	$(PREFIX)/share/man/man1/user-pass-otp.sphinx.1 $(PREFIX)/share/man/man1/user-pass.sphinx.1 $(PREFIX)/share/man/man1/pipe2tmpfile.1

clean:
	rm -f *.1
	rm -f *.html

otp.sphinx.1: sphinx-x11.1
	ln -s $< $@
pass.sphinx.1: sphinx-x11.1
	ln -s $< $@
user-pass-otp.sphinx.1: sphinx-x11.1
	ln -s $< $@
user-pass.sphinx.1: sphinx-x11.1
	ln -s $< $@
getacc-user-pass.sphinx.1: sphinx-x11.1
	ln -s $< $@

%.1: %.md
	pandoc -s  -o $@ $<

%.html: %.md
	pandoc -s -o $@ $<
