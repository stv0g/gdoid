/* $Id: ipsec.h,v 1.4.2.1 2011/10/18 03:26:56 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/ipsec.h,v $ */

/*	$OpenBSD: ipsec.h,v 1.15 2000/12/12 01:44:59 niklas Exp $	*/
/*	$EOM: ipsec.h,v 1.42 2000/12/03 07:58:20 angelos Exp $	*/

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

#ifndef _IPSEC_H_
#define _IPSEC_H_

#include <netinet/in.h>

#include "ipsec_doi.h"

/* according to IANA assignment, port 0x0000 and proto 0xff are reserved. */
#define IPSEC_PORT_ANY          0
#define IPSEC_ULPROTO_ANY       255
#define IPSEC_PROTO_ANY         255

/* mode of security protocol */
 /* NOTE: DON'T use IPSEC_MODE_ANY at SPD.  It's only use in SAD */
#define IPSEC_MODE_ANY          0       /* i.e. wildcard. */
#define IPSEC_MODE_TRANSPORT    1
#define IPSEC_MODE_TUNNEL       2
#define IPSEC_MODE_TCPMD5       3       /* TCP MD5 mode */

/*
  * Direction of security policy.
  * NOTE: Since INVALID is used just as flag.
  * The other are used for loop counter too.
  */
#define IPSEC_DIR_ANY           0
#define IPSEC_DIR_INBOUND       1
#define IPSEC_DIR_OUTBOUND      2
#define IPSEC_DIR_MAX           3
#define IPSEC_DIR_INVALID       4

/* Policy level */
 /*
  * IPSEC, ENTRUST and BYPASS are allowed for setsockopt() in PCB,
  * DISCARD, IPSEC and NONE are allowed for setkey() in SPD.
  * DISCARD and NONE are allowed for system default.
  */
#define IPSEC_POLICY_DISCARD    0       /* discard the packet */
#define IPSEC_POLICY_NONE       1       /* bypass IPsec engine */
#define IPSEC_POLICY_IPSEC      2       /* pass to IPsec */
#define IPSEC_POLICY_ENTRUST    3       /* consulting SPD if present. */
#define IPSEC_POLICY_BYPASS     4       /* only for privileged socket. */
#define IPSEC_POLICY_TCP        5       /* TCP MD5 policy */

#ifdef LINUX_PFKEY
/* Security protocol level */
#define IPSEC_LEVEL_DEFAULT     0       /* reference to system default */
#define IPSEC_LEVEL_USE         1       /* use SA if present. */
#define IPSEC_LEVEL_REQUIRE     2       /* require SA. */
#define IPSEC_LEVEL_UNIQUE      3       /* unique SA. */
#endif


struct group;
struct hash;
struct ike_auth;
struct message;
struct proto;
struct sa;

/*
 * IPSEC-specific data to be linked into the exchange struct.
 * XXX Should probably be two different structs, one for phase 1 and one
 * for phase 2 parameters.
 */
struct ipsec_exch {
  u_int flags;
  struct hash *hash;
  struct ike_auth *ike_auth;
  struct group *group;
  u_int16_t prf_type;
  u_int8_t  pfs;	/* 0 if no KEY_EXCH was proposed, 1 otherwise */

  /*
   * A copy of the initiator SA payload body for later computation of hashes.
   * Phase 1 only.
   */
  size_t sa_i_b_len;
  u_int8_t *sa_i_b;

  /* Diffie-Hellman values.  */
  size_t g_x_len;
  u_int8_t *g_xi;
  u_int8_t *g_xr;
  u_int8_t* g_xy;

  /* SKEYIDs.  XXX Phase 1 only?  */
  size_t skeyid_len;
  u_int8_t *skeyid;
  u_int8_t *skeyid_d;
  u_int8_t *skeyid_a;
  u_int8_t *skeyid_e;

  /* HASH_I & HASH_R.  XXX Do these need to be saved here?  */
  u_int8_t *hash_i;
  u_int8_t *hash_r;

  /* KEYMAT */
  size_t keymat_len;

  /* Phase 2.  */
  u_int8_t *id_ci;
  size_t id_ci_sz;
  u_int8_t *id_cr;
  size_t id_cr_sz;
};

#define IPSEC_EXCH_FLAG_NO_ID 1

struct ipsec_sa {
  /* Phase 1.  */
  u_int8_t hash;
  size_t skeyid_len;
  u_int8_t *skeyid_d;
  u_int8_t *skeyid_a;
  u_int16_t prf_type;

  /* Phase 2.  */
  u_int16_t group_desc;

  /* Tunnel parameters.  These are in network byte order.  */
  in_addr_t src_net;
  in_addr_t src_mask;
  in_addr_t dst_net;
  in_addr_t dst_mask;
  u_int8_t  tproto;
  u_int16_t sport;
  u_int16_t dport;
};

struct ipsec_proto {
  /* Phase 2.  */
  u_int16_t encap_mode;
  u_int16_t auth;
  u_int16_t keylen;
  u_int16_t keyrounds;
  u_int16_t addr_pres;
  u_int16_t sa_direction;

  /* This is not negotiated, but rather configured.  */
  int32_t replay_window;

  /* KEYMAT */
  u_int8_t *keymat[2];
};

struct ipsec_decode_arg {
  struct message *msg;
  struct sa *sa;
  struct proto *proto;
};

extern u_int8_t *ipsec_add_hash_payload (struct message *msg, size_t);
extern int ipsec_ah_keylength (struct proto *);
extern u_int8_t *ipsec_build_id (char *, size_t *);
extern int ipsec_decode_attribute (u_int16_t, u_int8_t *, u_int16_t, void *);
extern void ipsec_decode_transform (struct message *, struct sa *,
				    struct proto *, u_int8_t *);
extern int ipsec_esp_authkeylength (struct proto *);
extern int ipsec_esp_enckeylength (struct proto *);
extern int ipsec_fill_in_hash (struct message *msg);
extern int ipsec_gen_g_x (struct message *);
extern int ipsec_get_id (char *, int *, struct in_addr *, struct in_addr *,
			 u_int8_t *, u_int16_t *);
extern ssize_t ipsec_id_size (char *, u_int8_t *);
extern void ipsec_init (void);
extern int ipsec_initial_contact (struct message *msg);
extern int ipsec_is_attribute_incompatible (u_int16_t, u_int8_t *, u_int16_t,
					    void *);
extern int ipsec_keymat_length (struct proto *);
extern int ipsec_save_g_x (struct message *);
extern struct sa *ipsec_sa_lookup (in_addr_t, u_int32_t, u_int8_t);
extern void ipsec_set_network (u_int8_t *, u_int8_t *, struct ipsec_sa *);
extern int ipsec_sa_check_flow (struct sa *sa, void *v_arg);


extern char *ipsec_decode_ids(char *, u_int8_t *, size_t, u_int8_t *, size_t,
			      int);
extern int ipsec_clone_id(u_int8_t **, size_t *, u_int8_t *, size_t);

#endif /* _IPSEC_H_ */
