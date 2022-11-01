clean:

install: $(DESTDIR)$(prefix)/usr/bin/dmenu-sphinx $(DESTDIR)$(prefix)/usr/bin/exec-on-click $(DESTDIR)$(prefix)/usr/bin/getpwd $(DESTDIR)$(prefix)/usr/bin/type-pwd $(DESTDIR)$(prefix)/usr/share/doc/pwdsphinx-tools/README.x11.md

$(DESTDIR)$(prefix)/usr/bin/dmenu-sphinx: dmenu-sphinx
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/exec-on-click: exec-on-click
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/getpwd: getpwd
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/type-pwd: type-pwd
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/share/doc/pwdsphinx-tools/README.x11.md: README.md
	install -D -m 0644 $< $@

.PHONY: clean
