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
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_ENDIAN
#include <sys/endian.h>
#endif

#ifdef HAVE_MACHINE_PARAM
#include <machine/param.h>
#endif
#include <sys/ipc.h>
#include <sys/shm.h>
#include <syslog.h>
#include <assert.h>
#include <sys/time.h>
#include <time.h>

/* NTP SHM struct from NTP reference code refclock_shm.c */
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
#define	NUM_UNITS	4
struct shmTime	*shm;

/* Routine swiped from ntp refclock_hsm.c */
struct shmTime *getShmTime (int unit) {
	int shmid=0;

	assert (unit<NUM_UNITS); /* MAXUNIT is 4, so should never happen */
	shmid=shmget (NTP_SHM+unit, sizeof (struct shmTime), 
		      IPC_CREAT|(unit<2?0700:0777));
	if (shmid==-1) { /*error */
		// msyslog(LOG_ERR,"SHM shmget (unit %d): %s",unit,strerror(errno));
		return 0;
	}
	else { /* no error  */
		struct shmTime *p=(struct shmTime *)shmat (shmid, 0, 0);
		if ((int)(long)p==-1) { /* error */
			// msyslog(LOG_ERR,"SHM shmat (unit %d): %s",unit,strerror(errno));
			return 0;
		}
		return p;
	}
}

char *prog = 0;
void usage()
{
	fprintf(stderr, "Usage: %s [-g] [-u <unit>] [-p <port>] host\n", prog);
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
		    printf("Packet 0x6c incorrect length: %d, should be %d\n",
		    	len, 17+s->svs_in_fix);
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
		printf("Unhandled super packet type: %x\n", c);
		return -1;
		break;
	    }
	    break;

	default:
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

	struct timeval	tv;
	struct tm	tm;
	time_t		seconds;

	tsip_packet_t	p;

	for(i = 0; i < len; ++i)
	{
	    c = buf[i];
	    if (have_dle)
	    {
	    	switch(c)
		{
		case ETX:
		    /* Finished with the TSIP Packet, process it */
		    parse_tsip(tsip_buf, tsip_len, &p);
		    if (p.tsip_type == TSIP_PRIMARY_TIMING_PACKET)
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
	char		*port = "2947";
	char		*host = 0;
	int		gpsd = 0;

	int		c;

	int		gpssock;
	int		sockflags;
	struct addrinfo	*ai_gpsd, *ai_gpsd0, hints;
	int		gai_ret;
	const char	*cause = NULL;
	
	char		rbuf[2048];
	size_t		readlen;

	fd_set		fd_read, fd_write, fd_err;
	fd_set		fd_r, fd_w, fd_e;
	int		nfds;
	
	int		unit = 0;

	prog = strdup(argv[0]);
	/* Process options here */
	while ((c = getopt(argc, argv, "p:gu:")) != -1)
	{
	    switch(c)
	    {
	    case 'p':
	    	port = strdup(optarg);
		break;

	    case 'g':
	    	gpsd = 1;
		break;

	    case 'u':
	    	unit = atoi(optarg);
		if((unit < 0) || (unit >= NUM_UNITS))
		    usage();
		break;

	    default:
	    	usage();
		break;
	    }
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
	{
	    usage();
	}
	host = strdup(argv[0]);

	shm = getShmTime(unit);
	if (shm == 0)
	    err(EX_UNAVAILABLE, "Unable to initialize shared memory");

	memset(shm, 0, sizeof(*shm));
	shm->mode = 1;
	shm->precision = -1;
	shm->nsamples = 3;

	printf("Connecting to %s: %s\n", host, port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((gai_ret = getaddrinfo(host, port, &hints, &ai_gpsd0)) != 0)
	{
	    /* FIXME Should check for transient errors */
	    errx(EX_UNAVAILABLE, "%s: %s: %s", host, port, gai_strerror(gai_ret));
	}

	gpssock = -1;
	for (ai_gpsd = ai_gpsd0; ai_gpsd; ai_gpsd = ai_gpsd->ai_next)
	{
	    gpssock = socket(ai_gpsd->ai_family, ai_gpsd->ai_socktype, ai_gpsd->ai_protocol);
	    if (gpssock < 0)
	    {
		cause = "socket";
		continue;
	    }

	    if (connect(gpssock, ai_gpsd->ai_addr, ai_gpsd->ai_addrlen) < 0)
	    {
	    	cause = "connect";
		close(gpssock);
		gpssock = -1;
		continue;
	    }

	    break;	/* If we get here we have a live connection */
	}
	if (gpssock < 0)
	{
	    err(EX_UNAVAILABLE, "%s", cause);
	}
	freeaddrinfo(ai_gpsd0);
	printf("Connected\n");

	/* Let's just loop on the socket, and stuff whatever is returned into the file */
	/* Make the socket non-blocking */
	if ((sockflags = fcntl(gpssock, F_GETFL)) == -1)
	{
	    err(EX_OSERR, "fcntl");
	}
	sockflags |= O_NONBLOCK;
	fcntl(gpssock, F_SETFL, sockflags);

	FD_ZERO(&fd_read);
	FD_ZERO(&fd_write);
	FD_ZERO(&fd_err);

	FD_SET(gpssock, &fd_read);
	FD_SET(gpssock, &fd_err);

	// If we are connecting to gpsd put it in super-raw mode
	if (gpsd)
	    write(gpssock, "r2\n", 3);

	while (1)
	{
	    fd_r = fd_read;
	    fd_w = fd_write;
	    fd_e = fd_err;

	    nfds = select(FD_SETSIZE, &fd_r, &fd_w, &fd_e, 0);
	    if (nfds < 0)
	    {
	        err(EX_UNAVAILABLE, "select");
	    }
	    if (FD_ISSET(gpssock, &fd_r))
	    {
	    	/* We have data, read it and spew it to the output file */
		readlen = read(gpssock, rbuf, sizeof(rbuf));
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
		    /* Write to the output file */
		    read_tsip(rbuf, readlen);
		}
	    }
	}
}
