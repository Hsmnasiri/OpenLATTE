# ------------------------------------------------------------------
# Juliet.mk  --  build Juliet testcases in LATTE-compatible formats
#
# Variables you typically override on the make command line:
#   JULIET_ROOT = absolute path to juliet/C            (no trailing /)
#   SRC         = absolute path to the testcase .c file
#   CC          = gcc (or your cross compiler)
#
# Targets:
#   all        : build DBG (unstripped) + STRIPPED (.out)
#   dbg        : build unstripped debug binary
#   stripped   : strip debug + unneeded symbols (LATTE eval style)
#   fw         : small, optimised, stripped (firmware-like dyn)
#   static     : static linked (if toolchain supports) + stripped
#   clean      : remove build artifacts
#
# ------------------------------------------------------------------

# -------- user-configurable ---------------------------------------------------
JULIET_ROOT ?= $(error Please set JULIET_ROOT=/abs/path/to/juliet/C)
SRC         ?= $(error Please set SRC=/abs/path/to/testcase.c)
CC          ?= gcc
STRIP       ?= strip

# Juliet support code
SUPPORT_DIR  := $(JULIET_ROOT)/testcasesupport
SUPPORT_SRCS := $(wildcard $(SUPPORT_DIR)/*.c)
SUPPORT_INC  := -I$(SUPPORT_DIR)

# Basename (no dir, no .c)
BASENAME     := $(notdir $(basename $(SRC)))

# Output dirs
BUILD_DIR    := build
DBG_DIR      := $(BUILD_DIR)/dbg
STRIP_DIR    := $(BUILD_DIR)/stripped
FW_DIR       := $(BUILD_DIR)/fw
STATIC_DIR   := $(BUILD_DIR)/static

# Output files
DBG_BIN      := $(DBG_DIR)/$(BASENAME).unstripped
STRIP_BIN    := $(STRIP_DIR)/$(BASENAME).out
FW_BIN       := $(FW_DIR)/$(BASENAME)_fw.out
STATIC_BIN   := $(STATIC_DIR)/$(BASENAME)_static.out

# CFLAGS
CFLAGS_BASE  := -DINCLUDEMAIN $(SUPPORT_INC)
CFLAGS_DBG   := $(CFLAGS_BASE) -O0 -g
CFLAGS_REL   := $(CFLAGS_BASE) -O2
CFLAGS_FW    := $(CFLAGS_BASE) -Os -fomit-frame-pointer \
                -ffunction-sections -fdata-sections
LDFLAGS_FW   := -Wl,--gc-sections

# Static flags (will fail if static libs not installed)
CFLAGS_STATIC := $(CFLAGS_FW)
LDFLAGS_STATIC:= -static -static-libgcc $(LDFLAGS_FW)

# strip options (remove debug + unneeded symbols)
STRIPFLAGS   := --strip-debug --strip-unneeded

# ------------------------------------------------------------------
.PHONY: all dbg stripped fw static clean info dirs

all: dbg stripped

dbg: $(DBG_BIN)
stripped: $(STRIP_BIN)
fw: $(FW_BIN)
static: $(STATIC_BIN)

info:
	@echo "JULIET_ROOT = $(JULIET_ROOT)"
	@echo "SRC         = $(SRC)"
	@echo "SUPPORT_DIR = $(SUPPORT_DIR)"
	@echo "BASENAME    = $(BASENAME)"

dirs:
	@mkdir -p $(DBG_DIR) $(STRIP_DIR) $(FW_DIR) $(STATIC_DIR)

$(DBG_BIN): $(SRC) $(SUPPORT_SRCS) | dirs
	$(CC) $(CFLAGS_DBG) $^ -o $@

$(STRIP_BIN): $(DBG_BIN) | dirs
	cp $< $@
	$(STRIP) $(STRIPFLAGS) $@

$(FW_BIN): $(SRC) $(SUPPORT_SRCS) | dirs
	$(CC) $(CFLAGS_FW) $(LDFLAGS_FW) $^ -o $@
	$(STRIP) $(STRIPFLAGS) $@

$(STATIC_BIN): $(SRC) $(SUPPORT_SRCS) | dirs
	$(CC) $(CFLAGS_STATIC) $(LDFLAGS_STATIC) $^ -o $@
	$(STRIP) $(STRIPFLAGS) $@

clean:
	rm -rf $(BUILD_DIR)

 # ------------------------------------------------------------------:
 