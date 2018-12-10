MODNAME=luarsa
MODSO=$(MODNAME).so
OBJS=luarsa.o
#version = 1.0

LUA_VERSION =   5.1

## Linux/BSD
PREFIX ?=          /usr/local/nginx

LUA_INCLUDE_DIR ?= $(PREFIX)/include
LUA_LIB_DIR ?=     $(PREFIX)/lua/lib/lua/$(LUA_VERSION)

OPENSSL_INC_DIR=/usr/include
OPENSSL_LIB_DIR=/usr/lib64


INSTALL ?= install
LUA ?= lua

CFLAGS = -c -Wall -fpic 
LDFLAGS = -shared -L$(OPENSSL_LIB_DIR)
.PHONY: all clean 

CC = gcc 
RM = rm -f

all: $(MODSO) 

%.o : %.c
	$(CC) $(CFLAGS) $< -o $@ -I$(LUA_INC_DIR) -I$(OPENSSL_INC_DIR)


$(MODSO): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lcrypto -lssl

install: 
	$(INSTALL) -d $(LUA_LIB_DIR)
	$(INSTALL) luarsa.so $(LUA_LIB_DIR)

clean:
	$(RM) *.so *.o

test:
	@$(LUA) test_encrypt_decrypt.lua && echo "test_encrypt_decrypt test OK"
	@$(LUA) test_sign_check.lua && echo "test_sign_check test OK"
