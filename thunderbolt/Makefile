LDFLAGS += -lutil -g
CFLAGS += -g

all: tboltd gpsdclient

tboltd: tboltd.o
	$(CC) $(LDFLAGS) -o $(.TARGET) $(.ALLSRC)

tboltd.o: tboltd.c

gpsdclient: gpsdclient.o
	$(CC) $(LDFLAGS) -o $(.TARGET) $(.ALLSRC)

gpsdclient.o: gpsdclient.c
