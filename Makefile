CC = x86_64-w64-mingw32-gcc
CFLAGS = -O2 -Wall -Wno-unused-function

# Lua 5.2.3 source directory.
# Download lua-5.2.3.tar.gz from https://www.lua.org/ftp/lua-5.2.3.tar.gz
# Extract it and rename the inner directory to lua/ here: lua_injector/lua/
# So ./lua/src/lua.h must exist before building dinput8.dll.
LUA_DIR = lua/src
LUA_CFLAGS = -I$(LUA_DIR) -DLUA_COMPAT_ALL

# Lua core source files (no standalone apps: no lua.c, no luac.c)
LUA_SRCS = \
    lapi.c lauxlib.c lbaselib.c lbitlib.c lcode.c lcorolib.c lctype.c \
    ldblib.c ldebug.c ldo.c ldump.c lfunc.c lgc.c \
    llex.c lmem.c loadlib.c lobject.c lopcodes.c \
    lparser.c lstate.c lstring.c lstrlib.c ltable.c ltablib.c ltm.c \
    lundump.c lvm.c lzio.c
LUA_OBJS = $(patsubst %.c,obj/lua_%.o,$(LUA_SRCS))

PROXY_OBJS = obj/dinput8_proxy.o $(LUA_OBJS)

.PHONY: all clean

all: dinput8.dll

obj:
	mkdir -p obj

obj/dinput8_proxy.o: dinput8_proxy.c | obj
	$(CC) $(CFLAGS) $(LUA_CFLAGS) -c dinput8_proxy.c -o $@

obj/lua_%.o: $(LUA_DIR)/%.c | obj
	$(CC) $(CFLAGS) $(LUA_CFLAGS) -c $< -o $@

# __declspec(dllexport) in dinput8_proxy.c handles the export table —
# no .def file needed for x86-64 C linkage with GNU ld.
dinput8.dll: $(PROXY_OBJS)
	$(CC) -shared -o dinput8.dll $(PROXY_OBJS) -lkernel32

clean:
	if exist obj rmdir /s /q obj
	if exist dinput8.dll del /q dinput8.dll
