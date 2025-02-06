clean:

install: $(DESTDIR)$(prefix)/usr/bin/dmenu-sphinx $(DESTDIR)$(prefix)/usr/bin/exec-on-click \
	$(DESTDIR)$(prefix)/usr/bin/getpwd $(DESTDIR)$(prefix)/usr/bin/type-pwd \
	$(DESTDIR)$(prefix)/usr/bin/otp.sphinx $(DESTDIR)$(prefix)/usr/bin/pass.sphinx \
	$(DESTDIR)$(prefix)/usr/bin/user-pass-otp.sphinx $(DESTDIR)$(prefix)/usr/bin/user-pass.sphinx \
   $(DESTDIR)$(prefix)/usr/bin/getacc-user-pass.sphinx \
	$(DESTDIR)$(prefix)/usr/bin/sphinx-x11 $(DESTDIR)$(prefix)/usr/bin/pipe2tmpfile \
	$(DESTDIR)$(prefix)/usr/share/doc/pwdsphinx-tools/README.x11.md

$(DESTDIR)$(prefix)/usr/bin/dmenu-sphinx: dmenu-sphinx
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/exec-on-click: exec-on-click
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/getpwd: getpwd
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/type-pwd: type-pwd
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/sphinx-x11: sphinx-x11
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/pipe2tmpfile: pipe2tmpfile
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/otp.sphinx: sphinx-scripts/otp.sphinx
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/pass.sphinx: sphinx-scripts/pass.sphinx
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/user-pass-otp.sphinx: sphinx-scripts/user-pass-otp.sphinx
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/user-pass.sphinx: sphinx-scripts/user-pass.sphinx
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/bin/getacc-user-pass.sphinx: sphinx-scripts/getacc-user-pass.sphinx
	install -D -m 0755 $< $@

$(DESTDIR)$(prefix)/usr/share/doc/pwdsphinx-tools/README.x11.md: README.md
	install -D -m 0644 $< $@

.PHONY: clean
