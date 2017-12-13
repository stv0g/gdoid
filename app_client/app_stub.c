/* $Id: app_stub.c,v 1.1.2.2 2011/12/12 20:43:47 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/app_client/Attic/app_stub.c,v $ */

/* 
 * The license applies to all software incorporated in the "Cisco GDOI reference
 * implementation" except for those portions incorporating third party software 
 * specifically identified as being licensed under separate license. 
 *  
 *  
 * The Cisco Systems Public Software License, Version 1.0 
 * Copyright (c) 2001-2007 Cisco Systems, Inc. All rights reserved.
 * Subject to the following terms and conditions, Cisco Systems, Inc., 
 * hereby grants you a worldwide, royalty-free, nonexclusive, license, 
 * subject to third party intellectual property claims, to create 
 * derivative works of the Licensed Code and to reproduce, display, 
 * perform, sublicense, distribute such Licensed Code and derivative works. 
 * All rights not expressly granted herein are reserved. 
 * 1.      Redistributions of source code must retain the above 
 * copyright notice, this list of conditions and the following 
 * disclaimer.
 * 2.      Redistributions in binary form must reproduce the above 
 * copyright notice, this list of conditions and the following 
 * disclaimer in the documentation and/or other materials 
 * provided with the distribution.
 * 3.      The names Cisco and "Cisco GDOI reference implementation" must not 
 * be used to endorse or promote products derived from this software without 
 * prior written permission. For written permission, please contact 
 * opensource@cisco.com.
 * 4.      Products derived from this software may not be called 
 * "Cisco" or "Cisco GDOI reference implementation", nor may "Cisco" or 
 * "Cisco GDOI reference implementation" appear in 
 * their name, without prior written permission of Cisco Systems, Inc.
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE, TITLE AND NON-INFRINGEMENT ARE DISCLAIMED. IN NO EVENT 
 * SHALL CISCO SYSTEMS, INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY 
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. THIS LIMITATION OF LIABILITY SHALL NOT APPLY TO 
 * LIABILITY FOR DEATH OR PERSONAL INJURY RESULTING FROM SUCH 
 * PARTY'S NEGLIGENCE TO THE EXTENT APPLICABLE LAW PROHIBITS SUCH 
 * LIMITATION. SOME JURISDICTIONS DO NOT ALLOW THE EXCLUSION OR 
 * LIMITATION OF INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THAT 
 * EXCLUSION AND LIMITATION MAY NOT APPLY TO YOU. FURTHER, YOU 
 * AGREE THAT IN NO EVENT WILL CISCO'S LIABILITY UNDER OR RELATED TO 
 * THIS AGREEMENT EXCEED AMOUNT FIVE THOUSAND DOLLARS (US) 
 * (US$5,000). 
 *  
 * ====================================================================
 * This software consists of voluntary contributions made by Cisco Systems, 
 * Inc. and many individuals on behalf of Cisco Systems, Inc. For more 
 * information on Cisco Systems, Inc., please see <http://www.cisco.com/>.
 *
 * This product includes software developed by Ericsson Radio Systems.
 */ 

/*
 * app_stub -- This program demonstrates how an application 
 *              contacts a GDOI client daemon for keys and policy.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>

#include "../src/gdoi_app_num.h"
#ifdef IEC90_5_SUPPORT
#include "../src/gdoi_app_iec90_5_attr.h"
#endif
#ifdef SRTP_SUPPORT
#include "../src/gdoi_srtp_attr.h"
#endif

#define APPS_CLIENT_PIPE "/tmp/apps_to_gdoi"
#define GDOI_CLIENT_PIPE "/tmp/gdoi_to_app"

#define MAX_MSG_SIZE 500 /* Guess */
#define MAX_PRINT_BUF_LEN 80

#define ATTR_HDR_SZ 4

#define GET_RETRY_VALUE 30
#define NORMAL_POLL_VALUE 15

#define GET_NEW_KEYS_BEFORE_EXPIRATION_PERIOD 5

/* 
 * Supported applications
 * List must match the list in ../src/gdoi_app_num.cst.
 */
#ifdef SRTP_SUPPORT
#define APP_SRTP 	"srtp"
#endif
#define APP_IEC90_5	"iec90-5"

unsigned int apptype;

/*
 * HEADER TYPE
 */
struct cmd_header {
  short version;
  short command;
#define COMMAND_ADD 3 
#define COMMAND_GET 5 
  u_int32_t app_proto;
  int peer_errno;
  int sequence;
  int pid;
};

int retry_secs;
int poll_for_pushed_policy_secs;
int current_state;
unsigned int key_expiration_time;

#define INVALID_VALUE 0x0fffffff

typedef enum states_ {
	ERROR,
	NO_KEYS,
	HAVE_KEYS,
	ASKING_FOR_MORE_KEYS
} states;

#define GDOI_CLIENT_ATTR_GROUP_ID 		101
#define GDOI_CLIENT_ATTR_RETURN_PIPE 	102
#define GDOI_CLIENT_ATTR_GROUP_ADDRESS	103

/*
 * The following 
 */
#ifdef SRTP_SUPPORT
#define GDOI_PROTO_SRTP					100
#endif
#ifdef IEC90_5_SUPPORT
#define GDOI_PROTO_IEC90_5				101
#endif

/*
 * STRUCTURES
 *
 * Generic Header
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Version            |            Command            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             Errno                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            Sequence                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                              PID                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

int group;

int s_to_gdoi; 

void shutmedown (int sig)
{
	printf("error: shutting down due to signal %d\n", sig);
	close(s_to_gdoi);
	exit(1);
}

void err (char *tag)
{
    printf("error: %s", tag);
    if (errno) {
	printf(", errno=%s", strerror(errno));
    }
    printf("\n");
    exit(1);
}

u_int8_t *grow_buf (u_int8_t *old_buf, int *old_buf_sz, u_int8_t *build_buf, 
				int build_buf_sz)
{
  u_int8_t *new_buf;
  int new_buf_sz = *old_buf_sz + build_buf_sz;

  new_buf = realloc(old_buf, new_buf_sz);
  if (!new_buf)
    {
	  err("realloc failed");
	}
  memcpy((new_buf+*old_buf_sz), build_buf, build_buf_sz);
  *old_buf_sz = new_buf_sz;

  return new_buf;
}

void
encode_16 (u_int8_t *cp, short x)
{
  *cp++ = x >> 8;
  *cp = x & 0xff;
}

u_int16_t
decode_16 (u_int8_t *cp)
{
  return cp[0] << 8 | cp[1];
}

u_int32_t
decode_32 (u_int8_t *cp)
{
  return cp[0] << 24 | cp[1] << 16 | cp[2] << 8 | cp[3];
}

u_int8_t *
attribute_add_var (u_int8_t *buf, int *buf_sz, short type, char *value, short len)
{
  u_int8_t *new_buf, *ptr;
  int new_buf_sz;

  /*
   * Calculate size of new buffer needed
   */
  new_buf_sz = *buf_sz + len + ATTR_HDR_SZ;
  new_buf = realloc(buf, new_buf_sz);
  if (!new_buf)
    {
	  err("realloc failed");
	}
  ptr = new_buf + *buf_sz;
  encode_16(ptr, type);
  ptr += 2;
  encode_16(ptr, len);
  ptr += 2;

  memcpy(ptr, value, len);

  *buf_sz = new_buf_sz;
  return new_buf;
}

int
print_generic_attributes (u_int8_t *buf, size_t sz, int *lifetime)
{
  u_int8_t *attr;
  int fmt;
  u_int16_t type;
  u_int8_t *value;
  u_int16_t len;
  int i;
  u_int8_t display_buf[MAX_PRINT_BUF_LEN];

  printf("Generic Attributes:\n");
  for (attr = buf; attr < buf + sz; attr = value + len)
    {
      if (attr + 4 > buf + sz)
		return -1;
      type =  decode_16(attr) & 0x7fff;
      fmt = *attr >> 7;
      value = attr + (fmt ? 2 : 4);
      len = (fmt ? 2 : decode_16(attr+2));
      printf("  Format: %d, Type: %03d, Length: %02d Value: ", fmt, type, len);
      if (value + len > buf + sz)
		return -1;
      switch (type) {
	  case GDOI_CLIENT_ATTR_GROUP_ID:
	  	printf("Group ID %d (%#x)\n", 
			ntohl(decode_32(value)), ntohl(decode_32(value)));
		break;
	  case GDOI_CLIENT_ATTR_RETURN_PIPE:
		if (len >= MAX_PRINT_BUF_LEN) {
			len = MAX_PRINT_BUF_LEN - 1;
		}
		memcpy(display_buf, value, len);
		display_buf[len] = 0;
	  	printf("Return Pipe %s\n", display_buf);
		break;
	  case GDOI_CLIENT_ATTR_GROUP_ADDRESS:
		if (4 == len) {
			printf("Address: %x\n", decode_32(value));
		} else {
			printf("Address lenggh %d not supported\n", len);
		}
		break;
	  default:
	    printf("Unknown Attribute: %d\n", type);
		break;
	  }
    }
  printf("\n");
  return 0;
}

#ifdef IEC90_5_SUPPORT
static void
print_attribute_hex (u_int8_t *value, u_int16_t len)
{
	int i;

	for (i=0; i<len; i++)
	  {
		printf("%x", value[i]);
	  }
	printf("\n");
}

int
print_iec90_5_attributes (u_int8_t *buf, size_t sz, unsigned int *lifetime)
{
  u_int8_t *attr;
  int fmt;
  u_int16_t type;
  u_int8_t *value;
  u_int16_t len;
  u_int8_t display_buf[MAX_PRINT_BUF_LEN];

  printf("Attributes:\n");
  for (attr = buf; attr < buf + sz; attr = value + len)
    {
      if (attr + 4 > buf + sz)
		return -1;
      type =  decode_16(attr) & 0x7fff;
      fmt = *attr >> 7;
      value = attr + (fmt ? 2 : 4);
      len = (fmt ? 2 : decode_16(attr+2));
      printf("  Format: %d, Type: %03d, Length: %02d Value: ", fmt, type, len);
      if (value + len > buf + sz)
		return -1;
      switch (type) {
	  case IEC90_5_OID:
	  	printf("OID:\n\t");
		print_attribute_hex(value, len);
		break;
	  case IEC90_5_LIFETIME_SECS:
	  	printf("Lifetime of IEC90-5 keys: %d\n", htonl(decode_32(value)));
		/*
		 * Return the lifetime if requested.
		 */
		if (lifetime) {
			*lifetime = 2<<htonl(decode_32(value));
		}
		break;
	  case IEC90_5_KEYID:
	  	printf("Key ID: %d\n", decode_16(value));
		break;
	  case IEC90_5_AUTH_ALG:
	  	printf("Authentication Algorighm: %d\n", decode_16(value));
		break;
	  case IEC90_5_AUTH_KEY_SIZE:
	  	printf("Authentication Key Size: %d\n", decode_16(value));
		break;
	  case IEC90_5_AUTH_KEY:
	  	printf("Authentication Key:\n\t");
		print_attribute_hex(value, len);
		break;

	  default:
	    printf("Unknown Attribute: %d\n", type);
		break;
	  }
    }
  printf("\n");
  return 0;
}
#endif
#ifdef SRTP_SUPPORT
int
print_srtp_attributes (u_int8_t *buf, size_t sz, int *lifetime)
{
  u_int8_t *attr;
  int fmt;
  u_int16_t type;
  u_int8_t *value;
  u_int16_t len;
  int i;
  u_int8_t display_buf[MAX_PRINT_BUF_LEN];

  printf("Attributes:\n");
  for (attr = buf; attr < buf + sz; attr = value + len)
    {
      if (attr + 4 > buf + sz)
		return -1;
      type =  decode_16(attr) & 0x7fff;
      fmt = *attr >> 7;
      value = attr + (fmt ? 2 : 4);
      len = (fmt ? 2 : decode_16(attr+2));
      printf("  Format: %d, Type: %03d, Length: %02d Value: ", fmt, type, len);
      if (value + len > buf + sz)
		return -1;
      switch (type) {
	  case SRTP_SOURCE_ID:
	  	printf("Source Address");
		break;
	  case SRTP_DEST_ID:
	  	printf("Destination Address");
		break;
	  case SRTP_MASTER_KEY:
	  	printf("Master Key:\n\t");
		for (i=0; i<len; i++)
		  {
			printf("%x", value[i]);
		  }
		printf("\n");
		break;
	  case SRTP_MASTER_SALT_KEY:
	  	printf("Master Salt Key:\n\t");
		for (i=0; i<len; i++)
		  {
			printf("%x", value[i]);
		  }
		printf("\n");
		break;
	  case SRTP_REPLAY_WINDOW:
	  	printf("Replay window size: %d\n", decode_16(value));
		break;
	  case SRTP_KD_RATE:
	  	printf("KD Rate: %d\n", decode_16(value));
		break;
	  case SRTP_LIFETIME:
	  	printf("Lifetime of SRTP keys: %d (%d packets)\n", 
			decode_16(value), 2<<decode_16(value));
		/*
		 * Return the lifetime if requested.
		 */
		if (lifetime) {
			*lifetime = 2<<decode_16(value);
		}
		break;
	  case SRTP_SRTCP_LIFETIME:
	  	printf("Lifetime of SRTCP keys: %d (%d packets)\n", 
			decode_16(value), 2<<decode_16(value));
		break;

	  default:
	    printf("Unknown Attribute: %d\n", type);
		break;
	  }
    }
  printf("\n");
  return 0;
}
#endif

void
print_hdr (struct cmd_header *hdr)
{
  printf("  Version:  %d\n", hdr->version);
  printf("  Command:  %d\n", hdr->command);
  printf("  App Proto:%d\n", hdr->app_proto);
  printf("  Errno:    %d\n", hdr->peer_errno);
  printf("  Sequence: %d\n", hdr->sequence);
  printf("  Pid:      %d\n", hdr->pid);
  printf("\n");
}

u_int8_t *create_initial_GET_packet (int *len)
{
  u_int8_t *buf, *start_attr;
  struct cmd_header *hdr;
  int buf_sz;

  /*
   * Create header. It's a fixed size.
   *
   * NOTE: A real application would want to save the header for comparison to
   *       IPC replies from the GDOI GM.
   */
  hdr = calloc(1, sizeof(struct cmd_header));
  if (!hdr)
    {
	  err("calloc failure");
    }
  hdr->version = 1;
  hdr->command = COMMAND_GET;
  hdr->app_proto = apptype;
  srand(time(NULL));
  hdr->sequence = rand();
  hdr->pid = (int) getpid();

  printf("Sending packet:\n");
  print_hdr(hdr);

  buf = (u_int8_t *) hdr;
  buf_sz = sizeof(struct cmd_header);

  /*
   * Add attributes
   */
  start_attr = buf + buf_sz;
  buf = attribute_add_var(buf, &buf_sz, 
  						  GDOI_CLIENT_ATTR_GROUP_ID, 
						  (char *)&group, 4);
  buf = attribute_add_var(buf, &buf_sz, 
  						  GDOI_CLIENT_ATTR_RETURN_PIPE, GDOI_CLIENT_PIPE, 
						  strlen(GDOI_CLIENT_PIPE));

  print_generic_attributes(buf + sizeof(struct cmd_header), 
 				  buf_sz - sizeof(struct cmd_header), NULL);
  printf("\n");

  *len = buf_sz;
  return buf;
}

void
analyze_returned_ADD_packet (u_int8_t *buf, int len, unsigned int *lifetime)
{
  struct cmd_header *hdr;

  hdr = (struct cmd_header *) buf;

  printf("Returned Packet:\n");
  print_hdr(hdr);

  switch (hdr->app_proto) {
#ifdef IEC90_5_SUPPORT
	case GDOI_PROTO_IEC90_5:
  		print_iec90_5_attributes(buf + sizeof(struct cmd_header), 
 				  			  len - sizeof(struct cmd_header),
				  			  lifetime);
		break;
#endif
#ifdef SRTP_SUPPORT
	case GDOI_PROTO_SRTP:
  		print_srtp_attributes(buf + sizeof(struct cmd_header), 
 				  			  len - sizeof(struct cmd_header),
				  			  lifetime);
		break;
#endif
	default:
		printf("Unsupported protocol %d\n", hdr->app_proto);
		break;
  }
}

int
connect_to_gdoi (void)
{
  int s, ret;
  struct sockaddr_un pipe;

  s = socket (AF_LOCAL, SOCK_STREAM, 0);
  if (s < 0)
    {
	  err("socket open failed");
	  return -1;
    }
  
  bzero(&pipe, sizeof(struct sockaddr_un));
  pipe.sun_family = AF_LOCAL;
  strncpy(pipe.sun_path, APPS_CLIENT_PIPE, sizeof(pipe.sun_path)-1);

  ret = connect(s, (struct sockaddr *)&pipe, sizeof(pipe));
  if (ret < 0)
    {
	  err("connect failed");
	  return -1;
    }

  return s;
}

int
create_return_sock (void)
{
  int s, ret;
  struct sockaddr_un pipe;

  s = socket (AF_LOCAL, SOCK_STREAM, 0);
  if (s < 0)
    {
	  err("socket open failed");
	  return;
    }

  unlink(GDOI_CLIENT_PIPE);
  
  bzero(&pipe, sizeof(struct sockaddr_un));
  pipe.sun_family = AF_LOCAL;
  strncpy(pipe.sun_path, GDOI_CLIENT_PIPE, sizeof(pipe.sun_path)-1);

  ret = bind(s, (struct sockaddr *)&pipe, sizeof(pipe));
  if (ret < 0)
    {
	  err("bind failed");
	  return;
    }

  ret = listen(s, 1024);
  if (ret < 0)
    {
	  err("listen failed");
	  return;
    }

   return s;
}

/*
 * Send a request for keys.
 */
void
ask_for_keys (int s)
{
	int ret;
	u_int8_t *data_out;
	int data_out_len;
	struct msghdr msg;
	struct iovec iov[1];

	data_out = create_initial_GET_packet(&data_out_len);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	iov[0].iov_base = data_out;
	iov[0].iov_len = data_out_len;
	msg.msg_control = 0;
	msg.msg_controllen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(s, &msg, 0);
	if (ret < 0) {
		err("sendmsg failed");
		return;
	}
  
	/*
	 * Set the retry timer.
	 */
	retry_secs = GET_RETRY_VALUE;

	/*
	 * Cleanup
	 */
	free(data_out);
	data_out_len = 0;
}

void
handle_ADD_packet (u_int8_t *data_in, int num_bytes)
{
    unsigned int lifetime;

	if (num_bytes) {
		analyze_returned_ADD_packet(data_in, num_bytes, &lifetime);
		/*
	     * Now that we have keys, reset the timer to reflect the lifetime of
		 * the keys. 
		 *
		 * It may be that we get an un-requested update before
		 * that time.
		 */
		current_state = HAVE_KEYS;
		if (lifetime) {
			key_expiration_time = time(NULL) + lifetime;
			/* 
			 * Don't need to retry anymore 
			 */
			retry_secs = INVALID_VALUE; 
		} else {
			printf("WARNING: No lifetime given by GDOI. Re-trying.\n");
		}
	} else {
		printf("\nGDOI closed the connection\n");
		exit(0);
    }
}

/*
 * Decide how long to sleep based on the the current state.
 */
int
until_next_event (void)
{
	int sleep_time;

	if (retry_secs < poll_for_pushed_policy_secs) {
		sleep_time = retry_secs;
	} else {
		sleep_time = poll_for_pushed_policy_secs;
	}
	printf("Sleeping for %d seconds.\n", sleep_time);
	return sleep_time;
}

main (argc, argv)
int argc;
char **argv;
{
	int s_from_gdoi, c;
	int ret;
	u_int8_t data_in[1024];
	int data_in_len;
	int cc;
	char *usage="[ -a <appname> ] -g <group_number>";
	char *appname;

	struct sockaddr_un from;
	int from_len;

	int flags;

	/*
	 * Option processing 
	 */
	while (1) {
		cc = getopt(argc, argv, "a:g:");
		if (cc == -1) {
		  break;
		}
		switch (cc) {
		case 'a':
		    appname = optarg;
		    apptype = 0;
#ifdef IEC90_5_SUPPORT
			if (!strncmp(APP_IEC90_5, appname, strlen(APP_IEC90_5)))
				apptype = GDOI_PROTO_IEC90_5;
#endif
#ifdef SRTP_SUPPORT
			if (!strncmp(APP_SRTP, appname, strlen(APP_SRTP)))
				apptype = GDOI_PROTO_SRTP;
#endif
			if (!apptype) {
				printf("Unknown GDOI app %s\n", appname);
			}
			break;
		case 'g':
			group = atoi(optarg);
			break;
		default:
			printf("Unknown option %c\n", cc);
			printf("Usage: %s %s\n", argv[0], usage);
			exit(1);
		}
	}

	if (!group || !apptype) {
		printf("Usage: %s %s\n", argv[0], usage);
		exit(1);
	}

	current_state = NO_KEYS;

	s_to_gdoi = connect_to_gdoi();
	if (s_to_gdoi < 0) {
		return;
    }

	signal(SIGTERM, shutmedown);
	signal(SIGHUP, shutmedown);

	s_from_gdoi = create_return_sock();

	/*
	 * Make the first request for keys.
	 */
	ask_for_keys(s_to_gdoi);

    /* 
     * Setup the return pipe.
     */
    c = accept(s_from_gdoi, (struct sockaddr *)&from, (socklen_t *)&from_len);
  	if (c < 0) {
		err("accept failed");
	  	exit(1);
    }

  	/*
   	 * Make it non-blocking so we can poll it later.
   	 */
  	if ((flags = fcntl(c, F_GETFL, 0)) < 0) {
      	err("F_GETFL error");
  	}
  	flags |= O_NONBLOCK;
  	if (fcntl(c, F_SETFL, flags) < 0) {
	  	err("F_SETFL error");
  	}

  	/*
     * Setup initial timer values.
     */
	poll_for_pushed_policy_secs = NORMAL_POLL_VALUE;
	key_expiration_time = 0;

  	/*
     * Wait for something to happen.
     * 1. If no keys are returned within n seconds, try again.
     * 2. If an ADD message with keys is returned:
     *    a. handle them
     *    b. set a timer slightly before the lifetime ends 
     * 3. If an unsolicited ADD message with new keys is received:
     *    a. stop the timer.
     *    b. handle them.
     *    c. reset the timer to slightly before th next lifetime ends.
     */
	while (1) {
		/*
	     * Sleep until we need to check the socket or ask for keys.
	     */
	  	sleep(until_next_event());

	  	/*
	     * Read in non-blocking mode.
	     */
	  	ret = recvfrom(c, &data_in, MAX_MSG_SIZE, 0, NULL, NULL);
	  	if (ret < 1) {
			switch (errno) {
		  	case EAGAIN:
				/*
			 	 * GDOI hasn't sent anything yet.
			 	 */
				if ((current_state == NO_KEYS) ||
					(current_state == ASKING_FOR_MORE_KEYS)) {
					printf("\nAsking for Keys Again.\n");
					ask_for_keys(s_to_gdoi);
				} 
				/*
				 * Nothing to do if we already have keys -- we were just 
				 * checking in case GDOI pushed new keys to us.
				 */
				break;
		  	default:
		 		err("recvfrom failed");
		 		return;
 	 	  	}
		} else {
			/*
			 * BUG! It could be the GDOI was interrupted while sending us
			 * a response, in which case we may have only some of the
			 * payload. We're ignoring that this in this sample.
			 */
	  		handle_ADD_packet(data_in, ret);
		}

		/*
	 	 * Check if we need to ask for new keys. I.e., GDOI didn't give us any
	 	 * replacement keys so we need to ask for them.
	 	 *
	 	 * We want to ask for new keys GET_NEW_KEYS_BEFORE_EXPIRATION_PERIOD 
	 	 * seconds before the end of the actual lifetime, which gives us some 
	 	 * time to get another update before the current keys expire.
	 	 */
		printf("Key Expiration time: %d, Current time: %lld\n",
				key_expiration_time, (long long int) time(NULL));
		printf("Currrent State: %d\n", current_state);

		if ((key_expiration_time - time(NULL)) <=
				GET_NEW_KEYS_BEFORE_EXPIRATION_PERIOD) {
			ask_for_keys(s_to_gdoi);
			current_state = ASKING_FOR_MORE_KEYS;
		}

		/*
	 	 * If the keys expire without replacement, then we need to change state
	 	 * and ask again.
	 	 */
		if (key_expiration_time < time(NULL)) {
			ask_for_keys(s_to_gdoi);
			current_state = NO_KEYS;
		}
	}
}
