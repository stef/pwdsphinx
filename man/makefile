all: sphinx.1 oracle.1 bin2pass.1 websphinx.1 getpwd.1 exec-on-click.1 type-pwd.1 dmenu-sphinx.1 sphinx-x11.1 sphage.1
 
install: $(PREFIX)/share/man/man1/sphinx.1 $(PREFIX)/share/man/man1/oracle.1 $(PREFIX)/share/man/man1/bin2pass.1 \
	$(PREFIX)/share/man/man1/getpwd.1 $(PREFIX)/share/man/man1/exec-on-click.1 $(PREFIX)/share/man/man1/type-pwd.1 \
	$(PREFIX)/share/man/man1/dmenu-sphinx.1 $(PREFIX)/share/man/man1/sphinx-x11.1 $(PREFIX)/share/man/man1/sphage.1 \
	$(PREFIX)/share/man/man1/websphinx.1

clean:
	rm -f *.1

%.1: %.md
	pandoc -s  -o $@ $<
