/* $Id: key_api.c,v 1.4.4.1 2011/10/18 03:26:56 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/key_api.c,v $ */

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

/*	$OpenBSD: sysdep.c,v 1.8 2001/02/24 03:59:58 angelos Exp $	*/
/*	$EOM: sysdep.c,v 1.9 2000/12/04 04:46:35 angelos Exp $	*/

/*
 * Copyright (c) 1998, 1999 Niklas Hallqvist.  All rights reserved.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "sysdep.h"

#include "util.h"

#ifdef NEED_SYSDEP_APP
#include "app.h"
#include "conf.h"
#include "ipsec.h"

#ifdef USE_PF_KEY_V2
#include "pf_key_v2.h"
#define KEY_API(x) pf_key_v2_##x
#else
#include <net/encap.h>
#include "pf_encap.h"
#define KEY_API(x) pf_encap_##x
#endif

#endif /* NEED_SYSDEP_APP */
#include "log.h"

#if defined(LINUX_PFKEY) || defined(OSX)
#define IPSEC_LEVEL_BYPASS 0
#define IP_AUTH_LEVEL 1
#define IP_ESP_TRANS_LEVEL 1
#define IP_ESP_NETWORK_LEVEL 1
#endif

extern char *__progname;

/* Return the basename of the command used to invoke us.  */
char *
sysdep_progname ()
{
  return __progname;
}

/* As regress/ use this file I protect the sysdep_app_* stuff like this.  */
#ifdef NEED_SYSDEP_APP
/*
 * Prepare the application we negotiate SAs for (i.e. the IPsec stack)
 * for communication.  We return a file descriptor useable to select(2) on.
 */
int
sysdep_app_open ()
{
  return KEY_API(open) ();
}

/*
 * When select(2) has noticed our application needs attendance, this is what
 * gets called.  FD is the file descriptor causing the alarm.
 */
void
sysdep_app_handler (int fd)
{
  KEY_API (handler) (fd);
}

/* Check that the connection named NAME is active, or else make it active.  */
void
sysdep_connection_check (char *name)
{
  KEY_API (connection_check) (name);
}

/*
 * Generate a SPI for protocol PROTO and the source/destination pair given by
 * SRC, SRCLEN, DST & DSTLEN.  Stash the SPI size in SZ.
 */
u_int8_t *
sysdep_ipsec_get_spi (size_t *sz, u_int8_t proto, struct sockaddr *src,
		      int srclen, struct sockaddr *dst, int dstlen,
                      u_int32_t seq)
{
  if (app_none)
    {
      *sz = IPSEC_SPI_SIZE;
      /* XXX should be random instead I think.  */
      return (u_int8_t *)strdup ("\x12\x34\x56\x78");
    }
  return KEY_API (get_spi) (sz, proto, src, srclen, dst, dstlen, seq);
}

/* Force communication on socket FD to go in the clear.  */
int
sysdep_cleartext (int fd)
{
  int level;

  if (app_none)
    return 0;

  /*
   * Need to bypass system security policy, so I can send and
   * receive key management datagrams in the clear.
   */
#ifdef FREEBSD_PFKEY_EXT
  level = IPSEC_POLICY_BYPASS;
  if (setsockopt (fd, IPPROTO_IP, IP_IPSEC_POLICY, (char *)&level, sizeof level)
      == -1)
    {
      log_error ("sysdep_cleartext: "
		 "setsockopt (%d, IPPROTO_IP, IP_IPSEC_POLICY, ...) failed", fd);
      return -1;
    }
  if (setsockopt (fd, IPPROTO_IP, IPSECCTL_DEF_ESP_TRANSLEV, (char *)&level,
		  sizeof level) == -1)
    {
      log_error ("sysdep_cleartext: "
		 "setsockopt (%d, IPPROTO_IP, IPSECCTL_DEF_ESP_TRANSLEV, ...) "
		 "failed", fd);
      return -1;
    }
  if (setsockopt (fd, IPPROTO_IP, IPSECCTL_DEF_ESP_NETLEV, (char *)&level,
		  sizeof level) == -1)
    {
      log_error("sysdep_cleartext: "
		"setsockopt (%d, IPPROTO_IP, IPSECCTL_DEF_ESP_NETLEV, ...) "
		 "failed", fd);
      return -1;
    }
#else
  level = IPSEC_LEVEL_BYPASS;
  if (setsockopt (fd, IPPROTO_IP, IP_AUTH_LEVEL, (char *)&level, sizeof level)
      == -1)
    {
      log_error ("sysdep_cleartext: "
		 "setsockopt (%d, IPPROTO_IP, IP_AUTH_LEVEL, ...) failed", fd);
      return -1;
    }
  if (setsockopt (fd, IPPROTO_IP, IP_ESP_TRANS_LEVEL, (char *)&level,
		  sizeof level) == -1)
    {
      log_error ("sysdep_cleartext: "
		 "setsockopt (%d, IPPROTO_IP, IP_ESP_TRANS_LEVEL, ...) "
		 "failed", fd);
      return -1;
    }
  if (setsockopt (fd, IPPROTO_IP, IP_ESP_NETWORK_LEVEL, (char *)&level,
		  sizeof level) == -1)
    {
      log_error("sysdep_cleartext: "
		"setsockopt (%d, IPPROTO_IP, IP_ESP_NETWORK_LEVEL, ...) "
		 "failed", fd);
      return -1;
    }
#endif
  return 0;
}

int
sysdep_ipsec_delete_spi (struct sa *sa, struct proto *proto, int incoming)
{
  if (app_none)
    return 0;
  return KEY_API (delete_spi) (sa, proto, incoming);
}

int
sysdep_ipsec_enable_sa (struct sa *sa, struct sa *isakmp_sa)
{
  if (app_none)
    return 0;
  return KEY_API (enable_sa) (sa, isakmp_sa);
}

int
sysdep_ipsec_group_spis (struct sa *sa, struct proto *proto1,
			 struct proto *proto2, int incoming)
{
  if (app_none)
    return 0;
  return KEY_API (group_spis) (sa, proto1, proto2, incoming);
}

int
sysdep_ipsec_set_spi (struct sa *sa, struct proto *proto, int incoming)
{
  if (app_none)
    return 0;
  return KEY_API (set_spi) (sa, proto, incoming);
}
#endif
