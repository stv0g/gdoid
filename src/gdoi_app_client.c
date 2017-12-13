/* $Id: gdoi_app_client.c,v 1.1.4.3 2011/12/12 20:43:47 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/Attic/gdoi_app_client.c,v $ */

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
 * gdoi_app_client.c -	Code to send/receive messages from GDOI 
 * 			applications.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>
#ifdef NOT_LINUX
#include <sys/sockio.h>
#endif
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/un.h>

#include "log.h"
#include "util.h"
#include "string.h"
#include "transport.h"
#include "attribute.h"
#include "message.h"
#include "exchange.h"
#include "sa.h"
#include "gdoi_num.h"
#include "gdoi_app_num.h"
#include "gdoi_app_client.h"
#ifdef IEC90_5_SUPPORT
#include "gdoi_phase2.h" /* To get struct gdoi_kd_decode_arg */
#include "gdoi_iec90_5_protos.h"
#endif
#ifdef SRTP_SUPPORT
#include "gdoi_phase2.h" /* To get struct gdoi_kd_decode_arg */
#include "gdoi_srtp_protos.h"
#endif

#define FALSE 0
#define TRUE  1

#define APP_CLIENT_PIPE "/tmp/apps_to_gdoi"

extern int sigpiped;

#define ATTR_SIZE (50 * ISAKMP_ATTR_VALUE_OFF)

struct gdoi_app_group_info_type {
  struct cmd_header hdr;
  int group_id;
  char address[7]; /* Possible address for ID type, depends on app type */
  char pipe_name[80];
}; 

struct gdoi_app_transport {
  struct transport transport;
  struct gdoi_app_group_info_type gdoi_app_group_info;
  int s;
  int return_s;
  int listening_socket_only;
  int master_client_transport; /* One on which to accept connections */
};

void gdoi_app_remove (struct transport *);
static void gdoi_app_report(struct transport *);
static int gdoi_app_fd_set(struct transport *, fd_set *, int);
static int gdoi_app_fd_isset(struct transport *, fd_set *);
static void gdoi_app_handle_message(struct transport *);

static struct transport_vtbl gdoi_app_transport_vtbl = {
  { 0 }, "app",
  NULL,
  gdoi_app_remove,
  gdoi_app_report,
  gdoi_app_fd_set,
  gdoi_app_fd_isset,
  gdoi_app_handle_message,
  /* gdoi_app_send_message */ NULL,
  /* gdoi_app_get_dst */ NULL,
  /* gdoi_app_get_src */ NULL
};

void
gdoi_app_client_init (void)
{
  int s, ret;
  struct gdoi_app_transport *t = 0;
  struct sockaddr_un pipe;
  mode_t old_umask;
  int on = 1;
 
  /*
   * Add the GDOI Application  method to the transport list
   */
  transport_method_add (&gdoi_app_transport_vtbl);

  /*
   * Create the IPC socket, and add it as a transport session.
   */
  t = malloc (sizeof *t);
  if (!t)
    {
      log_print ("gdoi_app_client_init: malloc (%d) failed", sizeof *t);
      return;
    }

  t->transport.vtbl = &gdoi_app_transport_vtbl;

  s = socket (AF_LOCAL, SOCK_STREAM, 0);
  if (s < 0)
    {
	  log_error ("gdoi_app_client_init: socket failed");
	  return;
    }

  ret = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));
  if (ret < 0)
    {
	  log_error ("gdoi_app_client_init: bind failed");
	  return;
	}

  /*
   * Make sure it's not left over from another run.
   */
  unlink(APP_CLIENT_PIPE);

  /*
   * The mode of the pipe must be readable by all, so we need to adjust
   * our umask accordingly.
   */
  old_umask = umask(0044);
  
  bzero(&pipe, sizeof(struct sockaddr_un));
  pipe.sun_family = AF_LOCAL;
  strncpy(pipe.sun_path, APP_CLIENT_PIPE, sizeof(pipe.sun_path)-1);

  ret = bind(s, (struct sockaddr *) &pipe, SUN_LEN(&pipe));
  if (ret < 0)
    {
	  log_error ("gdoi_app_client_init: bind failed");
	  return;
	}

  /*
   * Reset the process umask for security reasons.
   */
  (void) umask(old_umask);
  
  ret = listen(s, 1024);
  if (ret < 0)
    {
	  log_error ("listen failed");
	  return;
    }

  /*
   * Set the open socket in the transport structure.
   */
  t->s = s;
  t->return_s = 0;
  t->listening_socket_only = TRUE;
  t->master_client_transport = TRUE;

  transport_add (&t->transport);
  transport_reference (&t->transport);
  t->transport.flags |= TRANSPORT_LISTEN;
}

void
gdoi_app_remove (struct transport *t)
{
  free (t);
}

static void
gdoi_app_report (struct transport *t)
{
  log_print ("gdoi_app_report: Got Here!");
}

/*
 * Set transport T's socket in FDS, return a value useable by select(2)
 * as the number of file descriptors to check.
 */
static int
gdoi_app_fd_set (struct transport *t, fd_set *fds, int bit)
{
  struct gdoi_app_transport *u = (struct gdoi_app_transport *)t;

  if (bit)
    FD_SET (u->s, fds);
  else {
	/*
	 * Hack! Asssume both sockets need to be cleared.
	 * BEW: But this code doesn't seem to be getting called when the pipe is
	 *      closed .... need to diagnose.
	 */
    log_print ("gdoi_app_fd_set: Clearing sockets.");
    FD_CLR (u->s, fds);
    FD_CLR (u->return_s, fds);
  }

  return u->s + 1;
}

/* Check if transport T's socket is set in FDS.  */
static int
gdoi_app_fd_isset (struct transport *t, fd_set *fds)
{
  struct gdoi_app_transport *u = (struct gdoi_app_transport *)t;

  return FD_ISSET (u->s, fds);
}

int gdoi_app_decode_attribute (u_int16_t type, u_int8_t *value, u_int16_t len,
							   void *arg)
{
  struct gdoi_app_group_info_type *ptr = 
	  	(struct gdoi_app_group_info_type *) arg;

  switch (type)
    {
	case GDOI_CLIENT_ATTR_GROUP_ID:
	  ptr->group_id = htonl(decode_32(value));
	  break;
	case GDOI_CLIENT_ATTR_GROUP_ADDRESS:
	  if (len < 7) { /* Largest address is MAC address (6 octets) */
	  	memcpy(ptr->address, value, len);
	  	ptr->address[len] = 0; /* Terminate the string */
	  } else {
		log_print ("gdoi_app_decode_attribute: Bad address length %d\n", len);
		return -1;
	  }
	  break;
	case GDOI_CLIENT_ATTR_RETURN_PIPE:
	  memcpy(ptr->pipe_name, value, len);
	  ptr->pipe_name[len] = 0; /* Terminate the string */
	  break;
	default:
      log_print ("gdoi_app_decode_attribute: Attribute not valid: %d", 
			  	  type);
	  return -1;
	}

return 0;
    
}
extern LIST_HEAD (transport_list, transport) transport_list;

struct gdoi_app_transport *
gdoi_app_transport_search (int gid)
{
  struct transport *t;
  struct gdoi_app_transport *u;

  for (t = LIST_FIRST (&transport_list); t; t = LIST_NEXT (t, link)) {
    if (t->flags & TRANSPORT_LISTEN) {
		  /*
		   * Restrict the search to GDOI application transports.
		   * NOTE: This logic only allows on application client per group.
		   */
		  if (!strcmp(t->vtbl->name, gdoi_app_transport_vtbl.name)) {
				  u = (struct gdoi_app_transport *)t;
				  if (gid == u->gdoi_app_group_info.group_id) {
					  /*
					   * Got it!
					   */
				  	  return u;
				  }
		  }
	 }
  }
  return NULL;
}

/*
 * For now, just stuff the info into a global struct. We can't yet
 * correlate an incoming msg with a finished GDOI session anyway, so 
 * have to restrict ourselves to one connection at a time.
 */
int
gdoi_app_parse_msg (char *msg, int msg_len, struct gdoi_app_transport *u)
{
  struct cmd_header *hdr = (struct cmd_header *)msg;

  /*
   * Sanity check the header
   */
  if (hdr->version != 1)
    {
	  log_error("App header unsupported version: %d\n", hdr->version);
	  return -1;
	}
  u->gdoi_app_group_info.hdr.version = hdr->version;
  if (hdr->command != COMMAND_REQUEST)
    {
	  log_error("App header unsupported command: %d\n", hdr->command);
	  return -1;
	}
  u->gdoi_app_group_info.hdr.command = hdr->command;
  u->gdoi_app_group_info.hdr.app_proto = hdr->app_proto;
  u->gdoi_app_group_info.hdr.sequence = hdr->sequence;
  u->gdoi_app_group_info.hdr.pid = hdr->pid;

  attribute_map (((u_int8_t *)msg + sizeof(struct cmd_header)), 
  			 	 (msg_len - sizeof(struct cmd_header)),
  				 gdoi_app_decode_attribute, 
				 &u->gdoi_app_group_info);
  return 0;
}

int
connect_to_client (char *out_fn)
{
  int s, ret;
  struct sockaddr_un pipe;

  s = socket (AF_LOCAL, SOCK_STREAM, 0);
  if (s < 0)
    {
	  log_error("socket open failed");
	  return -1;
    }
  

  bzero(&pipe, sizeof(struct sockaddr_un));
  pipe.sun_family = AF_LOCAL;
  strncpy(pipe.sun_path, out_fn, sizeof(pipe.sun_path)-1);

  ret = connect(s, (struct sockaddr *) &pipe, sizeof(pipe));
  if (ret < 0)
    {
	  log_error("connect failed: %s\n", out_fn);
	  return -1;
    }

  return s;
}

/* 
 * Clone a listen transport U, record a destination RADDR for outbound use.  
 */
static struct transport *
group_app_clone (struct gdoi_app_transport *u, int new_socket)
{
  struct transport *t;
  struct gdoi_app_transport *u2;

  t = malloc (sizeof *u);
  if (!t)
    {
      log_error ("group_app_clone: malloc (%d) failed", sizeof *u);
      return 0;
    }
  u2 = (struct gdoi_app_transport *)t;

  memcpy (u2, u, sizeof *u);
  u2->s = new_socket;
  u2->master_client_transport = FALSE;

  transport_add (t);
  
  t->flags |= TRANSPORT_LISTEN;

  return t;
}


/*
 * A message has arrived on transport T's socket.  If T is single-ended,
 * clone it into a double-ended transport which we will use from now on.
 * Package the message as we want it and continue processing in the message
 * module.
 */
static void
gdoi_app_handle_message (struct transport *t)
{
  struct gdoi_app_transport *u = (struct gdoi_app_transport *)t;
  struct transport *client_t;
  struct gdoi_app_transport *client_u;
  struct sockaddr_un from;
  int from_len = sizeof(from);
  struct message *msg;
  struct msghdr sock_msg;
  struct iovec iov[1];
  int c;
  char data_in[80];
  char name[80];
  int ret, count;
  struct cmd_header *hdr;

  if (u->master_client_transport)
    {
	  /*
	   * Do accepts on this one.
  	   *
   	   * Accept happens after the select has woken.
   	   * Only do this is this is a new connection on the listening socket.
   	   */
  	  c = accept(u->s, (struct sockaddr *) &from, (socklen_t *)&from_len);
  	  if (c < 0)
      	{
	  	  log_error ("gdoi_app_handle_message: accept failed");
	  	  return;
        }
	  /*
   	   * Make a specialized GDOI Application transport structure out of the 
	   * incoming transport.
       */
  	  client_t = group_app_clone (u, c);
  	  if (!client_t)
      	{
	  	  log_error("gdoi_app_handle_message: group_app_clone failed");
      	  return;
	  	}
  	  client_u = (struct gdoi_app_transport *)client_t;
	} else {
	  client_t = t;
	  client_u = u;
	  c = u->s;
	}

  /*
   * Read and process the message.
   */
  sock_msg.msg_name = NULL;
  sock_msg.msg_namelen = 0;
  sock_msg.msg_control = 0;
  sock_msg.msg_controllen = 0;
  iov[0].iov_base = data_in;
  iov[0].iov_len = 80;
  sock_msg.msg_iov = iov;
  sock_msg.msg_iovlen = 1;

  count = recvmsg (c, &sock_msg, 0);
  if (count < 0)
    {
	  log_error("gdoi_app_handle_message: recvmsg failed");
	  return;
    }
  if (count == 0)
    {
	  /*
	   * Assume the problem comes from the transmit pipe closing down.
	   */
	  log_print("gdoi_app_handle_message: "
				    "app pipe assumed closed. Deleting pipes to/from client");
	  ret = close(client_u->s);
	  if (ret < 0)
		{
	  	  log_error("gdoi_app_handle_message: close of s failed");
		}
	  ret = close(client_u->return_s);
	  if (ret < 0)
		{
	  	  log_error("gdoi_app_handle_message: close of return_s failed");
		}
	  transport_release(client_t);
	  return;
	}
  
  ret = gdoi_app_parse_msg (data_in, count, client_u);
  if (ret < 0)
    {
  	  return;
    }

  if (u->master_client_transport)
    {
	  /*
	   * If we just created this transport, connect back to the client.
	   */
  	  client_u->return_s = 
			connect_to_client(&client_u->gdoi_app_group_info.pipe_name[0]);
  	  if (client_u->return_s< 0)
      	{
	  	  log_error("gdoi_app_handle_message: connect_to_client failed");
		  return;
      	}
  	  client_u->listening_socket_only = FALSE;
	}

  msg = message_alloc (client_t, (u_int8_t *)data_in, count);
  if (!msg)
    {
	  log_error("message_alloc failed");
      return;
	}

  /*
   * Kick off IKE based on the group-id passed in the message using msg.
   * 
   * HACK! Require a policy named "Group-XXXXX" where XXXXX is the number
   * of the group. This makes it easy to find the right phase 1 to kick off.
   * We need to first parse the message to find the group id. 
   *
   * BUG: We should handle re-transmissions gracefully. E.g., don't force a
   * re-registration if one is already in progress.
   */
  sprintf(name, "Group-%d", client_u->gdoi_app_group_info.group_id);
  hdr = malloc(sizeof(struct cmd_header));
  if (!hdr) {
	log_error("gdoi_app_handle_message: failed to allocated hdr bytes");
    return;
  }
  hdr->pid = client_u->gdoi_app_group_info.hdr.pid;
  hdr->sequence = client_u->gdoi_app_group_info.hdr.sequence;

  log_print ("gdoi_app_handle_message: Starting exchange %s", name);
  exchange_establish(name, 0, 0);
}

/*
 * Deliver the application data back to the correct application. 
 */
int
gdoi_app_deliver_app_data (u_int32_t type, struct sa *sa)
{
  u_int8_t *attr_start, *attr;
  char *buf;
  struct cmd_header *hdr;
  struct gdoi_app_transport *client_u;
  struct proto *proto;
  int buf_len;
  int ret;
  int gid;

  proto = TAILQ_FIRST (&sa->protos);
  if (!proto)
    {
      log_error ("gdoi_app_deliver_app_data: Application SA proto data missing");
      return -1;
    }

  /*
   * Find the first transport asking for key info for this group using the
   * special group name semantic.  This is to deal with the HACK! in 
   * gdoi_app_handle_message().
   */
  if (strncmp(sa->name, "Group-", 6))
	{
	  log_error ("gdoi_app_deliver_app_data: Invalid group name: %s\n",
		  		  sa->name);
	  return -1;
	}
  sscanf(sa->name, "Group-%d", &gid);
  client_u = gdoi_app_transport_search(gid);  
  if (!client_u) 
    {
	  log_error ("gdoi_app_deliver_app_data: No transport found for "
			     "group id %d\n", gid);
	  return -1;
  	}

  if (type != client_u->gdoi_app_group_info.hdr.app_proto) {
	log_error ("gdoi_app_deliver_app_data: Protocol mismatch! "
			   "Expected:%d, Given by upper layer::%d\n", 
			   client_u->gdoi_app_group_info.hdr.app_proto, type);
	return -1;
  }

  if (!(void *)proto->data)
    {
      log_error ("gdoi_app_deliver_app_data: Application SA TEK data missing");
      return -1;
    }

  /*
   * Allocate a block for building attributes. It's sized large enough
   * so that we think it will avoid buffer overflows....
   */
  attr_start = attr = calloc(1, ATTR_SIZE);
  if (!attr_start)
    {
  	  log_error ("gdoi_app_deliver_app_data: malloc failed");
	  return -1;
	}

  /*
   * Call an Application-specific function to fill in the rest of the
   * attributes.
   */
  switch (type) {
#ifdef SRTP_SUPPORT
      case GDOI_PROTO_SRTP: 
	  attr = gdoi_srtp_add_attributes(attr, sa);
	  break;
#endif
#ifdef IEC90_5_SUPPORT
      case GDOI_PROTO_IEC90_5: 
	  attr = gdoi_iec90_5_add_attributes(attr, sa);
	  break;
#endif
      default:
	  log_error ("gdoi_app_deliver_app_data: No attribute support for "
		     "protocol %d", type);
	  return -1;
  }

  /*
   * Format the return message. Copy many of the fields from the originating
   * header to ensure they are the same.
   */
  buf_len = sizeof(struct cmd_header) + (attr - attr_start);
  buf = malloc(buf_len);

  hdr = (struct cmd_header *) buf;
  hdr->version = client_u->gdoi_app_group_info.hdr.version;
  hdr->command = COMMAND_REPLY;
  hdr->app_proto = type;
  hdr->sequence = client_u->gdoi_app_group_info.hdr.sequence;
  hdr->pid = client_u->gdoi_app_group_info.hdr.pid;
  hdr->ret_errno = 0;

  memcpy(buf + sizeof(struct cmd_header), attr_start, (attr - attr_start));

  free(attr_start);
  /*
   * Send the message.
   */
  ret = send(client_u->return_s, buf, buf_len, 0);
  if (ret < 0)
    {
	  log_error ("gdoi_app_deliver_app_data: send failed");
	   return -1;
	}

  return 0;
}
