LDFLAGS += -lutil -g
CFLAGS += -g

# Comment out the following to build on OS X */
#CFLAGS += -DHAVE_LIBUTIL=1
#CFLAGS += -DHAVE_ENDIAN=1
#CFLAGS += -DHAVE_MACHINE_PARAM=1

all: tboltd gpsdclient

tboltd: tboltd.o
	$(CC) $(LDFLAGS) -o tboltd tboltd.o

tboltd.o: tboltd.c

gpsdclient: gpsdclient.o
	$(CC) $(LDFLAGS) -o gpsclientd gpsdclient.o

gpsdclient.o: gpsdclient.c
