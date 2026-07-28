# LDAP BOF Collection Makefile
CC_X64 = x86_64-w64-mingw32-gcc
CC_X86 = i686-w64-mingw32-gcc
STRIP_X64 = x86_64-w64-mingw32-strip
STRIP_X86 = i686-w64-mingw32-strip
CFLAGS = -I _include -Os -masm=intel -fno-stack-protector -mno-stack-arg-probe -DBOF

OUTDIR = _bin/LDAP

GET_SRCS = get-users get-computers get-groups get-usergroups get-groupmembers get-object get-domaininfo get-maq get-writable get-delegation get-uac get-attribute get-spn get-acl get-rbcd
ADD_SRCS = add-user add-computer add-group add-groupmember add-ou add-sidhistory add-spn add-attribute add-uac add-delegation add-rbcd add-ace
SET_SRCS = set-password set-spn set-delegation set-attribute set-uac set-owner
MOVE_SRCS = move-object
REMOVE_SRCS = remove-groupmember remove-object remove-delegation remove-spn remove-attribute remove-rbcd remove-ace remove-uac

all: bof

bof: clean
	@mkdir -p $(OUTDIR) && echo '[*] Creating $(OUTDIR)/ directory'
	@echo '[*] Building GET commands...'
	@for src in $(GET_SRCS); do \
		$(CC_X64) $(CFLAGS) -c src/get/$$src.c -o $(OUTDIR)/$$src.x64.o && $(STRIP_X64) --strip-unneeded $(OUTDIR)/$$src.x64.o && echo "[+] $$src (x64)"; \
		$(CC_X86) $(CFLAGS) -c src/get/$$src.c -o $(OUTDIR)/$$src.x86.o && $(STRIP_X86) --strip-unneeded $(OUTDIR)/$$src.x86.o && echo "[+] $$src (x86)"; \
	done
	@echo '[*] Building ADD commands...'
	@for src in $(ADD_SRCS); do \
		$(CC_X64) $(CFLAGS) -c src/add/$$src.c -o $(OUTDIR)/$$src.x64.o && $(STRIP_X64) --strip-unneeded $(OUTDIR)/$$src.x64.o && echo "[+] $$src (x64)"; \
		$(CC_X86) $(CFLAGS) -c src/add/$$src.c -o $(OUTDIR)/$$src.x86.o && $(STRIP_X86) --strip-unneeded $(OUTDIR)/$$src.x86.o && echo "[+] $$src (x86)"; \
	done
	@echo '[*] Building SET commands...'
	@for src in $(SET_SRCS); do \
		$(CC_X64) $(CFLAGS) -c src/set/$$src.c -o $(OUTDIR)/$$src.x64.o && $(STRIP_X64) --strip-unneeded $(OUTDIR)/$$src.x64.o && echo "[+] $$src (x64)"; \
		$(CC_X86) $(CFLAGS) -c src/set/$$src.c -o $(OUTDIR)/$$src.x86.o && $(STRIP_X86) --strip-unneeded $(OUTDIR)/$$src.x86.o && echo "[+] $$src (x86)"; \
	done
	@echo '[*] Building MOVE commands...'
	@for src in $(MOVE_SRCS); do \
		$(CC_X64) $(CFLAGS) -c src/move/$$src.c -o $(OUTDIR)/$$src.x64.o && $(STRIP_X64) --strip-unneeded $(OUTDIR)/$$src.x64.o && echo "[+] $$src (x64)"; \
		$(CC_X86) $(CFLAGS) -c src/move/$$src.c -o $(OUTDIR)/$$src.x86.o && $(STRIP_X86) --strip-unneeded $(OUTDIR)/$$src.x86.o && echo "[+] $$src (x86)"; \
	done
	@echo '[*] Building REMOVE commands...'
	@for src in $(REMOVE_SRCS); do \
		$(CC_X64) $(CFLAGS) -c src/remove/$$src.c -o $(OUTDIR)/$$src.x64.o && $(STRIP_X64) --strip-unneeded $(OUTDIR)/$$src.x64.o && echo "[+] $$src (x64)"; \
		$(CC_X86) $(CFLAGS) -c src/remove/$$src.c -o $(OUTDIR)/$$src.x86.o && $(STRIP_X86) --strip-unneeded $(OUTDIR)/$$src.x86.o && echo "[+] $$src (x86)"; \
	done
	@echo '[*] Build complete!'

clean:
	@rm -rf $(OUTDIR)
