/* $Id: message.h,v 1.2.4.1 2011/10/18 03:26:56 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/message.h,v $ */

/*	$OpenBSD: message.h,v 1.14 2000/10/10 13:35:12 niklas Exp $	*/
/*	$EOM: message.h,v 1.51 2000/10/10 12:36:39 provos Exp $	*/

/* 
 * The license applies to all software incorporated in the "Cisco GDOI reference
 * implementation" except for those portions incorporating third party software 
 * specifically identified as being licensed under separate license. 
 *  
 *  
 * The Cisco Systems Public Software License, Version 1.0 
 * Copyright (c) 2001-2011 Cisco Systems, Inc. All rights reserved.
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
 * Copyright (c) 1998, 1999 Niklas Hallqvist.  All rights reserved.
 * Copyright (c) 1999 Angelos D. Keromytis.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Ericsson Radio Systems.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This code was written under funding by Ericsson Radio Systems.
 */

#ifndef _MESSAGE_H_
#define _MESSAGE_H_

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "isakmp.h"

struct event;
struct message;
struct proto;
struct sa;
struct transport;

struct payload {
  /* Link all payloads of the same type through here.  */
  TAILQ_ENTRY (payload) link;

  /* The pointer to the actual payload data.  */
  u_int8_t *p;

  /*
   * A pointer to the parent payload, used for proposal and transform payloads.
   */
  struct payload *context;

  /* Payload flags described below.  */
  int flags;
};

/* Payload flags.  */

/*
 * Set this when a payload has been handled, so we later can sweep over
 * unhandled ones.
 */
#define PL_MARK 1

/* A post-send chain of functions to be called.  */
struct post_send {
  /* Link to the next function in the chain.  */
  TAILQ_ENTRY (post_send) link;

  /* The actual function.  */
  void (*func) (struct message *);
};

struct message {
  /* Link message in send queues via this link.  */
  TAILQ_ENTRY (message) link;

  /* Message flags described below.  */
  u_int flags;

  /*
   * This is the transport the message either arrived on or will be sent to.
   */
  struct transport *transport;

  /*
   * This is the ISAKMP SA protecting this message.
   * XXX Needs to be redone to some keystate pointer or something.
   */
  struct sa *isakmp_sa;

  /* This is the exchange where this message appears.  */
  struct exchange *exchange;

  /*
   * A segmented buffer structure holding the messages raw contents.  On input
   * only segment 0 will be filled, holding all of the message.  On output, as
   * long as the message body is unencrypted each segment will be one payload,
   * after encryption segment 0 will be the unencrypted header, and segment 1
   * will be the encrypted payloads, all of them.
   */
  struct iovec *iov;

  /* The segment count.  */
  u_int iovlen;

  /* Pointer to the last "next payload" field.  */
  u_int8_t *nextp;

  /* "Smart" pointers to each payload, sorted by type.  */
#ifdef ORIGINAL
  TAILQ_HEAD (payload_head, payload) payload[ISAKMP_PAYLOAD_RESERVED_MIN];
#else
  /* GDOI has private payloads. */
  TAILQ_HEAD (payload_head, payload) payload[ISAKMP_PAYLOAD_PRIVATE_MAX];
#endif

  /* Number of times this message has been sent.  */
  int xmits;

  /* The timeout event causing retransmission of this message.  */
  struct event *retrans;

  /* The (possibly encrypted) message text, used for duplicate testing.  */
  u_int8_t *orig;
  size_t orig_sz;

  /*
   * Extra baggage needed to travel with the message.  Used transiently
   * in context sensitive ways.
   */
  void *extra;

  /*
   * Hooks for stuff needed to be done after the message has gone out to
   * the wire.
   */
  TAILQ_HEAD (post_send_head, post_send) post_send;
};

/* Message flags.  */

/*
 * This is the last message of an exchange, meaning it should not be
 * retransmitted other than if we see duplicates from our peer's last
 * message.
 */
#define MSG_LAST	1

/* The message has already been encrypted.  */
#define MSG_ENCRYPTED	2

/* The message is on the send queue.  */
#define MSG_IN_TRANSIT	4

extern int message_add_payload (struct message *, u_int8_t, u_int8_t *,
				size_t, int);
extern int message_add_sa_payload (struct message *);
extern struct message *message_alloc (struct transport *, u_int8_t *, size_t);
extern struct message *message_alloc_reply (struct message *);
extern u_int8_t *message_copy (struct message *, size_t, size_t *);
extern void message_drop (struct message *, int, struct proto *, int, int);
extern void message_dump_raw (char *, struct message *, int);
extern void message_free (struct message *);
extern int message_negotiate_sa (struct message *,
				 int (*) (struct exchange *, struct sa *,
					  struct sa *));
extern int message_recv (struct message *);
extern int message_register_post_send (struct message *,
				       void (*) (struct message *));
extern void message_post_send (struct message *);
extern void message_send (struct message *);
extern void message_send_expire (struct message *);
extern void message_send_delete (struct sa *);
extern int message_send_info (struct message *);
extern void message_send_notification (struct message *, struct sa *,
				       u_int16_t, struct proto *, int);
extern void message_setup_header (struct message *, u_int8_t, u_int8_t,
				  u_int8_t *);
extern int message_sort_payloads (struct message *, u_int8_t);
extern int message_validate_payloads (struct message *);

#endif /* _MESSAGE_H_ */
