/*
Copyright (c) 2010, Ralph N. Smith
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
Neither the name of the Ralph N. Smith nor the names of its
contributors may be used to endorse or promote products derived
from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>
#include <stdint.h>
#include <stdio.h>
#ifdef HAVE_ENDIAN
#include <sys/endian.h>
#endif
#ifdef HAVE_LIBUTIL
#include <libutil.h>
#endif
#include <termios.h>
#include <stdlib.h>

#ifdef MACHINE_PARAM
#include <machine/param.h>
#endif
#include <sys/ipc.h>
#include <sys/shm.h>
#include <syslog.h>
#include <assert.h>
#include <sys/time.h>
#include <time.h>

#include <arpa/inet.h>

#ifndef HAVE_ENDIAN
uint16_t be16dec(const void *buf)
{
	uint16_t	ret;
	ret = *(uint8_t *)buf;
	++buf;
	ret <<= 8;
	ret |= *(uint8_t *)buf;
	return ret;
}

uint32_t be32dec(const void *buf)
{
	uint32_t	ret;
	ret = *(uint8_t *)buf;
	++buf;
	ret <<= 8;
	ret |= *(uint8_t *)buf;
	++buf;
	ret <<= 8;
	ret |= *(uint8_t *)buf;
	++buf;
	ret <<= 8;
	ret |= *(uint8_t *)buf;
	return ret;
}
#endif

int detach = 1;
int verbose = 1;

/* NTP SHM struct from htp reference code refclock_shm.c */
struct shmTime {
	int    mode; /* 0 - if valid set
		      *       use values, 
		      *       clear valid
		      * 1 - if valid set 
		      *       if count before and after read of values is equal,
		      *         use values 
		      *       clear valid
		      */
	int    count;
	time_t clockTimeStampSec;
	int    clockTimeStampUSec;
	time_t receiveTimeStampSec;
	int    receiveTimeStampUSec;
	int    leap;
	int    precision;
	int    nsamples;
	int    valid;
	int    dummy[10]; 
};
#define	NTP_SHM		0x4e545030
struct shmTime	*shm = 0;

/* Routine swiped from ntp refclock_hsm.c */
struct shmTime *getShmTime (int unit) {
	int shmid=0;

	assert (unit<10); /* MAXUNIT is 4, so should never happen */
	shmid=shmget (NTP_SHM+unit, sizeof (struct shmTime), 
		      IPC_CREAT|(unit<2?0700:0777));
	if (shmid==-1) { /*error */
	        printf("SHM shmget (unit %d): %s",unit,strerror(errno));
		return 0;
	}
	else { /* no error  */
		struct shmTime *p=(struct shmTime *)shmat (shmid, 0, 0);
		if ((int)(long)p==-1) { /* error */
			printf("SHM shmat (unit %d): %s",unit,strerror(errno));
			return 0;
		}
		return p;
	}
}

int		tbolt_fd;

#define	CLIENT_BUF_SIZE	2048
typedef struct client_s
{
	struct client_s	*flink, *blink;
	int		fd;
	uint8_t		wbuf[CLIENT_BUF_SIZE];
	int		whead, wtail;
	uint8_t		rbuf[CLIENT_BUF_SIZE];
	int		rlen;
} client_t;
client_t	*clients = 0;

void set_client_fds(fd_set *rfd, fd_set *wfd, fd_set *efd)
{
	client_t	*c;

	for (c = clients; c; c = c->flink)
	{
	    if (c->whead != c->wtail)
	    	FD_SET(c->fd, wfd);
	    FD_SET(c->fd, rfd);
	    FD_SET(c->fd, efd);
	}
}

int add_client(int fd)
{
	client_t	*c;

	if (!detach)
	    printf("Adding client (%d)\n", fd);

	c = calloc(1, sizeof(*c));
	c->fd = fd;

	c->flink = clients;
	if (clients)
	    clients->blink = c;
	clients = c;

	return 0;
}

void client_remove(client_t *c)
{
	if (!detach)
	    printf("Detaching client (%d)\n", c->fd);

	close(c->fd);

	if (c == clients)			/* Are we the head? */
	{
	    if (!detach && verbose >= 1)
	        printf("Detaching head\n");
	    clients = clients->flink;
	    if (clients != 0)			/* anything left? */
	    {
	    	clients->blink = 0;		/*  yes, the head points back at nothing */
	    }
	    else
	    {
		if (!detach && verbose >= 1)
		    printf("Empty queue\n");
	    }
	}
	else if (c->flink == 0)			/*  no, are we the tail? */
	{
	    if (!detach && verbose >= 1)
	        printf("Detaching tail\n");
	    c->blink->flink = 0;		/*  previous is now the tail */
	}
	else					/*  OK, we're in the middle */
	{
	    if (!detach && verbose >= 1)
	        printf("Detaching interior\n");
	    c->blink->flink = c->flink;
	    c->flink->blink = c->blink;		/* Pluck ourselve out of the list */
	}

	free(c);
}

/* Queue data into a circular buffer for sending to a client */
/* Returns number of bytes actually queued */
int client_queue(void *buf, size_t len, client_t *c)
{
	size_t	l;
	int	consumed;

	consumed = 0;
	if (c->wtail >= c->whead)
	{
	    /* If we're here we can write up to the end of the buffer */
	    /* FIXME -- Subtle bug for when head = 0 and buffer is full */
	    l = CLIENT_BUF_SIZE - c->wtail;
	    if (!detach && verbose >= 4)
	        printf("l: %d\n", l);
	    if (len < l)
	    	l = len;
	    if (!detach && verbose >= 4)
	        printf("whead: %d, wtail: %d, l: %d\n", c->whead, c->wtail, l);
	    memcpy(c->wbuf + c->wtail, buf, l);
	    consumed += l;
	    len -= l;
	    buf += l;
	    c->wtail += l;
	    if (c->wtail >= CLIENT_BUF_SIZE)
	    {
		if (!detach && verbose >= 4)
		    printf("Buffer wrapped\n");
	    	c->wtail = 0;
	    }
	}
	/* Now we may or may not have data left, and can fill up to the tail */
	if (len)
	{
	    l = c->whead - c->wtail - 1;
	    if (!detach && verbose >= 4)
	        printf("B l: %d\n", l);
	    if (len < l)
	        l = len;
	    if (!detach && verbose >= 4)
	        printf("whead: %d, wtail: %d, l: %d\n", c->whead, c->wtail, l);
	    memcpy(c->wbuf + c->wtail, buf, l);
	    consumed += l;
	    c->wtail += l;
	}
	return consumed;
}

int client_read(client_t *c)
{
	ssize_t		ret;
	uint8_t		buf[2048];

	ret = read(c->fd, buf, sizeof(buf));
	switch(ret)
	{
	case 0:
	    // Client has closed the connection
	    client_remove(c);
	    break;

	case -1:
	    // Something is awry, is it fatal?
	    switch(errno)
	    {
	    case EINTR:
	    case EAGAIN:
	    	// No problem here, just continue
		break;

	    default:
		// Fatal problem on the connection
	    	client_remove(c);
		break;
	    }
	    break;

	default:
	    // Actually have data to use
	    if (!detach && verbose >= 1)
		printf("client (%d) read %d bytes\n", c->fd, ret);
	    /* FIXME -- Do this right */
	    write(tbolt_fd, buf, ret);
	}

	return(0);
}

int client_write(client_t *c)
{
	ssize_t		ret;
	size_t		l, consumed;

	if (c->whead == c->wtail)
	    return 0;

	consumed = 0;
	if (c->whead > c->wtail)
	{
	    /* Data is wrapped around, so let's write up to the end of the buffer */
	    /* Could probably do this more efficiently with iovecs, but I don't care
	       at the moment */
	    l = CLIENT_BUF_SIZE - c->whead;
	    if (!detach && verbose >= 4)
	        printf("Wrap: l: %d, head: %d\n", l, c->whead);
	    ret = write(c->fd, c->wbuf + c->whead, l);
	    if (ret == -1)
	    {
	    	switch(errno)
		{
		    case EAGAIN:
		    case EINTR:
		    	/* Temporary error, just bail */
			return consumed;
			break;

		    default:
		    	/* Failure of the peer, nuke it */
			client_remove(c);
			return -1;
			break;
		}
	    }
	    consumed += ret;
	    c->whead += ret;
	    if (c->whead >= CLIENT_BUF_SIZE)
	        c->whead = 0;
	    if (ret != l)
	        /* Didn't consume all data, so we will come back later */
		return consumed;
	}
	/* Now the data is not wrapped, send what we can */
	l = (c->wtail - c->whead);
	if (l)
	{
	    ret = write(c->fd, c->wbuf + c->whead, l);
	    if (ret == -1)
	    {
	    	switch(errno)
		{
		    case EAGAIN:
		    case EINTR:
		    	/* Temporary error, just bail */
			return consumed;
			break;

		    default:
		    	/* Failure of the peer, nuke it */
			client_remove(c);
			return -1;
			break;
		}
	    }
	    consumed += ret;
	    c->whead += ret;
	}
	return consumed;
}

int queue_clients(uint8_t *buf, size_t len)
{
	client_t	*c;

	for (c = clients; c; c = c->flink)
	    client_queue(buf, len, c);

	return 0;
}

int err_clients(fd_set *efd)
{
	client_t	*c, *flink;

	for (c = clients; c; c = flink)
	{
	    /* We do this because we will delete a client if it closes */
	    flink = c->flink;
	    if (FD_ISSET(c->fd, efd))
	    {
		if (!detach && verbose >= 4)
		    perror("Client write select");
	        client_remove(c);
	    }
	}

	return 0;
}

int write_clients(fd_set *wfd)
{
	client_t	*c, *flink;

	for (c = clients; c; c = flink)
	{
	    /* We do this because client_write will delete a client if it closes */
	    flink = c->flink;
	    if (FD_ISSET(c->fd, wfd))
	        client_write(c);
	}

	return 0;
}

int read_clients(fd_set *rfd)
{
	client_t	*c, *flink;

	for (c = clients; c; c = flink)
	{
	    /* We do this because client_read will delete a client if it closes */
	    flink = c->flink;
	    if (FD_ISSET(c->fd, rfd))
	        client_read(c);
	}

	return 0;
}

char *prog = 0;
void usage()
{
	fprintf(stderr, "Usage: %s [-t <tty>] [-v] [-p <port>] [-u <unit>] [-d]\n", prog);
	fprintf(stderr, "  -t <tty>:  Specify Thunderbolt serial port. Default 'cuau1'.\n");
	fprintf(stderr, "  -v:        Increase verbosity level.\n");
	fprintf(stderr, "  -p <port>: UDP port to listen for client connections. Default 45000.\n");
	fprintf(stderr, "  -u <unit>: Unit number for NTP shared memory driver. Default to none\n");
	fprintf(stderr, "  -d:        Do not detach and run in daemon mode.\n");
	exit(EX_USAGE);
}

typedef enum tsip_type_e
{
	TSIP_SATELLITE_TRACKING_STATUS = 0x5c,
	TSIP_SATELLITE_SELECTION_LIST = 0x6d,
	TSIP_PRIMARY_TIMING_PACKET = 0x8fab,
	TSIP_UNKNOWN = 0xffff
} tsip_type_t;

typedef struct tsip_satellite_tracking_status_s
{
	uint8_t	prn;
	uint8_t	slot;
	uint8_t	channel;
	uint8_t	acquisition_flag;
	uint8_t	ephemeris_flag;
	float	signal_level;
	float	last_measurement;
	float	elevation;
	float	azimuth;
	uint8_t	old_measurement_flag;
	uint8_t	integer_msec_flag;
	uint8_t	bad_data_flag;
	uint8_t	data_collection_flag;
} tsip_satellite_tracking_status_t;

typedef struct tsip_satellite_selection_list_s
{
	uint8_t	fix_dimension;
	uint8_t	fix_mode;
	uint8_t	svs_in_fix;
	float	pdop;
	float	hdop;
	float	vdop;
	float	tdop;
	int8_t	sv_prn[15];
} tsip_satellite_selection_list_t;

typedef struct primary_timing_packet_s
{
	uint32_t	gps_seconds_of_week;
	uint16_t	gps_week;
	int16_t		utc_offset;
	uint8_t		timing_flag;
	uint8_t		seconds;
	uint8_t		minutes;
	uint8_t		hour;
	uint8_t		day;
	uint8_t		month;
	uint16_t	year;
} primary_timing_packet_t;

typedef struct tsip_packet_s
{
	tsip_type_t	tsip_type;
	union {
		tsip_satellite_tracking_status_t	satellite_tracking_status;
		tsip_satellite_selection_list_t		satellite_selection_list;
		primary_timing_packet_t			primary_timing_packet;
	} data;
} tsip_packet_t;

int print_tsip(tsip_packet_t *p)
{
	switch(p->tsip_type)
	{
	case TSIP_SATELLITE_TRACKING_STATUS:
	    {
		tsip_satellite_tracking_status_t	*s;
		s = &p->data.satellite_tracking_status;
		printf("Satellite Tracking Status, ");
		printf("%d, ", s->prn);
		printf("%d, ", s->slot);
		printf("%d, ", s->channel);
		printf("%d, ", s->acquisition_flag);
		printf("%d, ", s->ephemeris_flag);
		printf("%f, ", s->signal_level);
		printf("%f, ", s->last_measurement);
		printf("%f, ", s->elevation);
		printf("%f, ", s->azimuth);
		printf("%d, ", s->old_measurement_flag);
		printf("%d, ", s->integer_msec_flag);
		printf("%d, ", s->bad_data_flag);
		printf("%d\n", s->data_collection_flag);
	    }
	    break;

	case TSIP_SATELLITE_SELECTION_LIST:
	    {
		tsip_satellite_selection_list_t		*s;
		int i;
		s = &p->data.satellite_selection_list;
		printf("Satellite Selection List, ");
		printf("%d, ", s->fix_dimension);
		printf("%d, ", s->fix_mode);
		printf("%d, ", s->svs_in_fix);
		printf("%f, ", s->pdop);
		printf("%f, ", s->hdop);
		printf("%f, ", s->vdop);
		printf("%f,", s->tdop);
		for (i = 0; i < s->svs_in_fix; ++i)
		{
		    printf(" %d", s->sv_prn[i]);
		}
		printf("\n");
	    }
	    break;

	case TSIP_PRIMARY_TIMING_PACKET:
	    {
		primary_timing_packet_t		*s;
		s = &p->data.primary_timing_packet;
		printf("Primary Timing Packet, ");
		printf("%d, ", s->gps_seconds_of_week);
		printf("%hu, ", s->gps_week);
		printf("%hd, ", s->utc_offset);
		printf("%hhu, ", s->timing_flag);
		printf("%hhu, ", s->seconds);
		printf("%hhu, ", s->minutes);
		printf("%hhu, ", s->hour);
		printf("%hhu, ", s->day);
		printf("%hhu, ", s->month);
		printf("%hu\n", s->year);
	    }
	    break;

	case TSIP_UNKNOWN:
	    printf("Unknown packet\n");
	    break;
	}
	return 0;
}

int parse_tsip(const uint8_t *buf, size_t len, tsip_packet_t *p)
{
	p->tsip_type = TSIP_UNKNOWN;
	uint8_t		c;
	int		i;

	if (!detach && verbose >= 2)
	{
	    for (i = 0; i < len; ++i)
		printf("%s%02hhx", i ? ":" : "", buf[i]);
	    printf("\n");
	}

	c = *buf;
	--len;
	++buf;

	switch(c)
	{
	case 0x5c:
	    p->tsip_type = TSIP_SATELLITE_TRACKING_STATUS;
	    if (len != 24)
	    {
		/* FIXME - need to set an error indication */
	        return(-1);
	    }
	    else
	    {
		tsip_satellite_tracking_status_t	*s;
		uint8_t	c;

		s = &p->data.satellite_tracking_status;
		s->prn = *(uint8_t *)buf;
		++buf;
		c = *(uint8_t *)buf;
		s->slot = (c & 0x07);
		s->channel = (c & 0xf8) >> 3;
		++buf;
		s->acquisition_flag = *(uint8_t *)buf;
		++buf;
		s->ephemeris_flag = *(uint8_t *)buf;
		++buf;
		*(uint32_t *)&s->signal_level = be32dec(buf);
		buf += 4;
		*(uint32_t *)&s->last_measurement = be32dec(buf);
		buf += 4;
		*(uint32_t *)&s->elevation = be32dec(buf);
		buf += 4;
		*(uint32_t *)&s->azimuth = be32dec(buf);
		buf += 4;
		s->old_measurement_flag = *(uint8_t *)buf;
		++buf;
		s->integer_msec_flag = *(uint8_t *)buf;
		++buf;
		s->bad_data_flag = *(uint8_t *)buf;
		++buf;
		s->data_collection_flag = *(uint8_t *)buf;
	    }
	    break;

	case 0x6d:
	    p->tsip_type = TSIP_SATELLITE_SELECTION_LIST;
	    {
		tsip_satellite_selection_list_t		*s;
		uint8_t	c;
		int	i;

		s = &p->data.satellite_selection_list;
		c = *(uint8_t *)buf;
		++buf;
		s->fix_dimension = c & 0x07;
		s->fix_mode = (c & 0x08) >> 3;
		s->svs_in_fix = (c & 0xf0) >> 4;

		/* Check the length of the packet */
		if (len != 17 + s->svs_in_fix)
		{
		    /*
			printf("Packet 0x6c incorrect length: %d, should be %d\n",
		    	len, 16+s->svs_in_fix);
		    */
		    return(-1);
		}

		/* OK, finish decoding the packet */
		*(uint32_t *)&s->pdop = be32dec(buf);
		buf += 4;
		*(uint32_t *)&s->hdop = be32dec(buf);
		buf += 4;
		*(uint32_t *)&s->vdop = be32dec(buf);
		buf += 4;
		*(uint32_t *)&s->tdop = be32dec(buf);
		buf += 4;

		for (i = 0; i < s->svs_in_fix; ++i)
		{
		    s->sv_prn[i] = *(int8_t *)buf;
		    ++buf;
		}
	    }
	    break;
	    
	case 0x8f:
	    /* Superpacket, let's find out what kind it is */
	    c = *buf;
	    --len;
	    ++buf;
	    switch(c)
	    {
	    case 0xab:
	    	/* Primary Timing Packet */
		if (len != 16)
		    return -1;
		p->tsip_type = TSIP_PRIMARY_TIMING_PACKET;
		{
		    primary_timing_packet_t	*s;
		    s = &p->data.primary_timing_packet;
		    s->gps_seconds_of_week = be32dec(buf);
		    buf += 4;
		    s->gps_week = be16dec(buf);
		    buf += 2;
		    s->utc_offset = be16dec(buf);
		    buf += 2;
		    s->timing_flag = *buf;
		    ++buf;
		    s->seconds = *buf;
		    ++buf;
		    s->minutes = *buf;
		    ++buf;
		    s->hour = *buf;
		    ++buf;
		    s->day = *buf;
		    ++buf;
		    s->month = *buf;
		    ++buf;
		    s->year = be16dec(buf);
		    buf += 2;
		}
		break;
		
	    default:
		if (!detach && verbose >= 2)
		    printf("Unhandled super packet type: %x\n", c);
		return -1;
		break;
	    }
	    break;

	default:
	    if (!detach && verbose >= 2)
		printf("Unhandled packet type: %x\n", c);
	    return -1;
	    break;
	}

	return 0;
}

#define	DLE	0x10
#define	ETX	0x03

int read_tsip(const char *buf, size_t len /* Stick in handler function */)
{
	static char	tsip_buf[2048];
	static int	tsip_len = 0;
	static int	have_dle = 0;
	static int	in_packet = 0;

	int		i;
	char		c;

	static struct timeval	tv;
	struct tm	tm;
	time_t		seconds;

	tsip_packet_t	p;

	for(i = 0; i < len; ++i)
	{
	    c = buf[i];
	    if (!detach && verbose >= 2)
		printf("%s%02hhx", i ? ":" : "", c);
	    if (have_dle)
	    {
	    	switch(c)
		{
		case ETX:
		    /* Finished with the TSIP Packet, process it */
		    if (!detach && verbose >= 2)
			printf("\n");
		    parse_tsip(tsip_buf, tsip_len, &p);
		    if (shm && p.tsip_type == TSIP_PRIMARY_TIMING_PACKET)
		    {
			tm.tm_sec = p.data.primary_timing_packet.seconds;
			tm.tm_min = p.data.primary_timing_packet.minutes;
			tm.tm_hour = p.data.primary_timing_packet.hour;
			tm.tm_mday = p.data.primary_timing_packet.day;
			tm.tm_mon = p.data.primary_timing_packet.month - 1;
			tm.tm_year = p.data.primary_timing_packet.year - 1900;
			seconds = timegm(&tm);
			if ((p.data.primary_timing_packet.timing_flag & 0x01) == 0)
			    seconds -= p.data.primary_timing_packet.utc_offset;

			shm->valid = 0;
		    	shm->count++;
			shm->clockTimeStampSec = seconds;
			shm->clockTimeStampUSec = 0;
			shm->receiveTimeStampSec = (time_t)tv.tv_sec;
			shm->receiveTimeStampUSec = (int)tv.tv_usec;
			shm->count++;
			shm->valid = 1;
		    }
		    if (!detach && verbose >= 2)
			print_tsip(&p);
		    tsip_len = 0;
		    in_packet = 0;
		    break;

		case DLE:
		    tsip_buf[tsip_len++] = c;
		    break;

		default:
		    /* Shouldn't happen, for now we just use the value as an escaped byte */
		    tsip_buf[tsip_len++] = c;
		    break;
		}
		have_dle = 0;
	    }
	    else if (in_packet)
	    {
	    	if (c == DLE)
		{
		    have_dle = 1;
		}
		else
		{
		    tsip_buf[tsip_len++] = c;
		}
	    }
	    else
	    {
	    	/* We are not in a TSIP Packet.  Skip until we are */
		if (c == DLE)
		{
		    // Get the time we start receiving the packet
		    gettimeofday(&tv, NULL);
		    in_packet = 1;
		}
	    }
	}
	return(i);
}

main(int argc, char *argv[])
{
	/* Default values, may be overridden by command-line options */
	char		*tty = "cuau1";
	char		*dev;

	int		c;
	int		ret;

	int		tbolt_flags;
	struct termios	tbolt_options;
	
	char		rbuf[2048];
	size_t		readlen;

	fd_set		fd_read, fd_write, fd_err;
	fd_set		fd_r, fd_w, fd_e;
	int		nfds;

	int		serv_sock, client_sock = -1;
	int		port = 45000;
	struct sockaddr_in	listen_addr;
	struct sockaddr_in	peer_addr;
	socklen_t	peer_addr_len;

	int unit = -1;

	prog = strdup(argv[0]);
	/* Process options here */
	while ((c = getopt(argc, argv, "t:p:du:v")) != -1)
	{
	    switch(c)
	    {
	    case 'p':
	    	port = atoi(optarg);
		break;

	    case 't':
	    	tty = strdup(optarg);
		break;

	    case 'd':
		detach = 0;
		break;

	    case 'v':
	    	++verbose;
		break;

	    case 'u':
	    	unit = atoi(optarg);
		break;

	    default:
	    	usage();
		break;
	    }
	}
	argc -= optind;
	argv += optind;

	if (unit != -1)
	{
	    shm = getShmTime(unit);
	    if (shm == 0)
		err(EX_UNAVAILABLE, "Unable to initialize shared memory");

	    memset(shm, 0, sizeof(*shm));
	    shm->mode = 1;
	    shm->precision = -1;
	    shm->nsamples = 3;
	}
	else
	{
	    shm = 0;
	}

	if (*tty == '/')
	    dev = strdup(tty);
	else
	    asprintf(&dev, "/dev/%s", tty);

#ifdef HAVE_LIBUTIL
	ret = uu_lock(tty);
	if (ret != UU_LOCK_OK)
	    errx(EX_UNAVAILABLE, "Can't lock '%s': %s", tty, uu_lockerr(ret));
#endif

	tbolt_fd = open(dev, O_RDWR | O_NOCTTY | O_NDELAY);
	if (tbolt_fd == -1)
	{
	    err(EX_UNAVAILABLE, "Can't open '%s'", dev);
	}

	tbolt_flags = fcntl(tbolt_fd, F_GETFL);
	tbolt_flags |= FNDELAY;
	fcntl(tbolt_fd, F_SETFL, tbolt_flags);

	/* Set up the serial port */
	tcgetattr(tbolt_fd, &tbolt_options);
	cfsetspeed(&tbolt_options, B9600);
	cfmakeraw(&tbolt_options);
	tbolt_options.c_cflag &= ~(CSIZE | PARENB | CSTOPB | CRTSCTS);
	tbolt_options.c_cflag |= CS8 | CLOCAL;
	tcsetattr(tbolt_fd, TCSANOW, &tbolt_options);

	/* Set up socket for listening to incoming network connections */
	serv_sock = socket(PF_INET, SOCK_STREAM, 0);
	if (serv_sock < 0)
	    err(EX_OSERR, "Can't create socket");
	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin_family = PF_INET;
	listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	listen_addr.sin_port = htons(port);

	if (bind(serv_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0)
	    err(EX_UNAVAILABLE, "Can't listen on port %d", port);
	listen(serv_sock, 5);

	if (detach)
	{
	    if (daemon(0, 0))
		err(EX_OSERR, "Can't detach");
	}

	/* Let's just loop on the socket, and stuff whatever is returned into the file */
	FD_ZERO(&fd_read);
	FD_ZERO(&fd_write);
	FD_ZERO(&fd_err);

	FD_SET(tbolt_fd, &fd_read);
	FD_SET(tbolt_fd, &fd_err);
	FD_SET(serv_sock, &fd_read);
	FD_SET(serv_sock, &fd_err);

	while (1)
	{
	    fd_r = fd_read;
	    fd_w = fd_write;
	    fd_e = fd_err;

	    set_client_fds(&fd_r, &fd_w, &fd_e);
	    nfds = select(FD_SETSIZE, &fd_r, &fd_w, &fd_e, 0);
	    if (nfds < 0)
	    {
		switch(errno)
		{
		case EINTR:
		    /* Loop back */
		    continue;
		    break;

		default:
		    err(EX_UNAVAILABLE, "select");
		}
	    }
	    err_clients(&fd_e);
	    if (FD_ISSET(tbolt_fd, &fd_r))
	    {
	    	/* We have data, read it and spew it to the output file */
		readlen = read(tbolt_fd, rbuf, sizeof(rbuf));
		if (readlen < 0)
		{
		    switch(errno)
		    {
		    case EAGAIN:
		    	/* No data, should not happen here. Go back to select */
			break;

		    default:
		    	/* Fatal error, barf */
			err(EX_UNAVAILABLE, "error reading socket");
			break;
		    }
		}
		else if (readlen == 0)
		{
		    /* Reached EOF on the socket */
		    errx(EX_IOERR, "Peer closed connection");
		}
		else
		{
		    read_tsip(rbuf, readlen);
		    queue_clients(rbuf, readlen);
		}
	    }

	    if (FD_ISSET(serv_sock, &fd_r))
	    {
	    	if (!detach && verbose >= 1)
		    printf("Data on the listening socket\n");

		peer_addr_len = sizeof(peer_addr);
	    	client_sock = accept(serv_sock, (struct sockaddr *)&peer_addr, &peer_addr_len);
		add_client(client_sock);
		if (!detach && verbose >= 1)
		    printf("Accepted connection from %s:%hu\n", inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));
	    }

	    read_clients(&fd_r);
	    write_clients(&fd_w);
	}
}
