clean:

install: $(DESTDIR)$(prefix)/usr/bin/dmenu-sphinx $(DESTDIR)$(prefix)/usr/bin/exec-on-click $(DESTDIR)$(prefix)/usr/bin/getpwd $(DESTDIR)$(prefix)/usr/bin/type-pwd $(DESTDIR)$(prefix)/usr/share/doc/README.x11.md

$(DESTDIR)$(prefix)/usr/bin/dmenu-sphinx: dmenu-sphinx.sh
	$(INSTALL) -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/exec-on-click: exec-on-click.sh
	$(INSTALL) -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/getpwd: getpwd.sh
	$(INSTALL) -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/type-pwd: type-pwd.sh
	$(INSTALL) -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/share/doc/README.x11.md: README.md
	$(INSTALL) -D -m 0644 $< $@

.PHONY: clean
