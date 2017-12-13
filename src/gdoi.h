/* $Id: gdoi.h,v 1.10.2.2 2011/12/05 20:26:54 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/gdoi.h,v $ */

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

#ifndef _GDOI_H_
#define _GDOI_H_
#include <netinet/in.h>
#include <hash.h>
#include "transport.h"
#ifdef USE_X509
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#endif

#define KEK_SPI_SIZE 16 
#define AES128_LENGTH 16
#define GCM_SALT_LENGTH 4

#define FALSE 0
#define TRUE  1

/*
 * Partial KEK information to pass as the next KEK. We only support channging
 * the SPI and encryption keys now, not the entire policy.
 */
struct next_gdoi_kek {
  u_int8_t spi[KEK_SPI_SIZE];
  u_int8_t *encrypt_iv;
  u_int8_t *encrypt_key; /* 3DES keys are stored as one value */
};

struct deleted_sa {
  TAILQ_ENTRY (deleted_sa) link;
  u_int32_t doi;
  u_int8_t protocol_type;
  u_int8_t spi[KEK_SPI_SIZE];
};

/*
 * Group KEK in-memory structure.
 */
struct gdoi_kek {
  TAILQ_ENTRY (gdoi_kek) link;
#define CREATE_NEW_KEK 0x01
#define SEND_NEW_KEK   0x02
#define CLEANING_UP    0x04
#define USE_EXCH_ONLY  0x08
  u_int32_t flags;
  u_int8_t *group_id;
  u_int32_t group_id_len;
  in_addr_t src_addr;
  in_addr_t dst_addr;
  u_int16_t sport;
  u_int16_t dport;
  u_int8_t spi[KEK_SPI_SIZE];
  u_int32_t current_seq_num;
  u_int32_t replay_bitmap;
  u_int16_t encrypt_alg;
  u_int16_t sig_hash_alg;
  u_int16_t sig_alg;
  u_int8_t *encrypt_iv;
  u_int8_t *encrypt_key; /* 3DES keys are stored as one value */
  u_int32_t encrypt_key_len; /* Only used for AES. Stored in bytes */
  u_int8_t *signature_key;
  u_int16_t signature_key_modulus_size; /* The "size" of the key in bits */
  u_int32_t signature_key_len;  /* Actual key size in bytes (PKCS#1 encaps) */
  struct next_gdoi_kek next_kek_policy; /* Send this info in a rekey message */
#ifdef USE_X509
  RSA *rsa_keypair;
#endif
  u_int32_t tek_timer_interval;
  u_int32_t kek_timer_interval;
  struct event *tek_lifetime_ev; /* Periodic TEK rekey timer (create new TEKS)*/
  struct event *kek_lifeime_ev; /* Periodic KEK rekey timer (new KEK keys) */
  int recv_sock;
  int send_sock;
  struct transport *send_transport;
  struct exchange *send_exchange;
  struct sockaddr_in recv_addr; /* Sender socket to join group */
  struct sockaddr_in send_addr; /* Sender socket to send to group */
  char *exchange_name;
  struct ip_mreq mreq;
  u_int16_t atd, dtd;
  /* GM SID variables */
  u_int32_t sid_length;
  u_int32_t number_sids;
#define MAX_GM_SIDS 5
  u_int32_t sids[MAX_GM_SIDS];
  u_int32_t number_sids_needed; 
  /* KS SID variables */
  u_int64_t sid_counter;
  TAILQ_HEAD (deleted_sa_head, deleted_sa) deleted_sa_list;
};

extern int (*gdoi_rekey_initiator[]) (struct message *);
extern int (*gdoi_rekey_responder[]) (struct message *);

void gdoi_rekey_init(void);
void gdoi_phase2_init(void);
struct gdoi_kek *gdoi_get_kek (u_int8_t *, size_t, int);
int gdoi_read_keypair (u_int8_t *, struct gdoi_kek *);
int gdoi_store_pubkey (u_int8_t *, int, struct gdoi_kek *);
int gdoi_kek_rekey_start (struct gdoi_kek *);
int gdoi_rekey_start (struct gdoi_kek *);
int gdoi_rekey_listen (struct gdoi_kek *);
int gdoi_rekey_setup_exchange (struct gdoi_kek *);
struct gdoi_kek *gdoi_get_kek_by_cookies (u_int8_t *);
struct gdoi_kek *gdoi_get_kek_by_transport (struct transport *);
struct gdoi_kek *gdoi_get_kek_by_name (char *);

u_int8_t *gdoi_build_tek_id_internal (int, struct in_addr, struct in_addr, 
	                              uint16_t, size_t *);
enum hashes xlate_gdoi_hash (u_int16_t);

#endif /* _GDOI_H_ */
