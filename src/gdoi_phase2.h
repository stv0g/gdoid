/* $Id: gdoi_phase2.h,v 1.7.2.2 2011/12/12 20:43:48 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/gdoi_phase2.h,v $ */

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


#ifndef _GDOI_PHASE2_H_
#define _GDOI_PHASE2_H_
#include <arpa/inet.h>  /* For struct in_addr */
#include "exchange.h"   /* For struct exchange */

#define HMAC_SHA_LENGTH 20
#define HMAC_SHA256_LENGTH 32
#define HMAC_MD5_LENGTH 16

struct message;

extern int (*gdoi_phase2_initiator[]) (struct message *msg);
extern int (*gdoi_phase2_responder[]) (struct message *msg);

struct tekspi {
  /* Link to the next SPI in the list */
  TAILQ_ENTRY (tekspi) link;

  /* SPI info */
  u_int8_t spi_sz;
  u_int8_t *spi;
};

/*
 * Group-specific data to be linked into the exchange struct.
 * XXX Should probably be two different structs, one for phase 1 and one
 * for phase 2 parameters.
 *
 * NOTE: This must remain the same as the ipsec_exch structure except for the 
 *       id payloads, or anything following the id payloads! A pointer of this 
 *       type is given to ipsec_decode_attribute() which currently thinks it's 
 *       a ipsec_exch structure.
 */
struct gdoi_exch {
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
  u_int8_t *id_gdoi;
  size_t id_gdoi_sz;

  /* TEK Types */
  u_int8_t  teks_type; /* All TEKs must be of the same type */

  /* Number of SIDs requested by a GM */
  u_int8_t num_sids;

  /* List of SPIs sent in the SA payload for sanity checking */
  TAILQ_HEAD (spi_head, tekspi) spis;
};

struct gdoi_kd_decode_arg {
  u_int8_t *sec_key;
  u_int8_t *int_key;
  size_t sec_key_sz; 
  size_t int_key_sz;
#ifdef IEC90_5_SUPPORT
  u_int8_t *custom_kd_payload;
  size_t custom_kd_payload_sz;
  u_int8_t custom_kd_payload_type;
#endif
};

enum msg_type { REKEY, REGISTRATION };

void gdoi_init(void);
extern u_int8_t *group_build_id (char *, size_t *);

/*
 * Generic GDOI functions referenced by the SRTP and IPSEC code.
 */
int gdoi_decode_kd_tek_attribute (u_int16_t, u_int8_t *, u_int16_t, void *);
u_int8_t *gdoi_grow_buf(u_int8_t *, size_t *, u_int8_t *, size_t);
int gdoi_get_id(char *, int *, struct in_addr *, struct in_addr *, 
		u_int16_t *);
int gdoi_current_sa (u_int8_t, struct sa *);
void gdoi_free_attr_payloads(void);
int gdoi_process_SA_payload (struct message *);
int gdoi_process_KD_payload (struct message *);
int gdoi_add_spi_to_list (struct exchange *, struct sa *);

int gdoi_setup_sa (struct sa *, struct proto **, int, int);

#endif /* _GDOI_PHASE2_H_ */
