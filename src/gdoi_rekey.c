/* $Id: gdoi_rekey.c,v 1.12.2.1 2011/10/18 03:26:55 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/gdoi_rekey.c,v $ */

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

#include "config.h"
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "sysdep.h"
#include "conf.h"
#include "log.h"
#include "timer.h"
#include "transport.h"
#include "crypto.h"
#include "exchange.h"
#include "message.h"
#include "udp.h"
#include "log.h"
#include "isakmp_fld.h"
#include "gdoi_fld.h"
#include "gdoi_num.h"
#include "gdoi_phase2.h"
#include "gdoi.h"
#include "doi.h"
#include "sa.h"
#include "libcrypto.h"
#include "util.h"
#include "ipsec_num.h"
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#define UDP_SIZE 65536

#define REKEY_HEADER_STRING "rekey"

/* If a system doesn't have SO_REUSEPORT, SO_REUSEADDR will have to do.  */
#ifndef SO_REUSEPORT
#define SO_REUSEPORT SO_REUSEADDR
#endif

static struct transport *rekey_udp_create (char *);
extern void udp_remove (struct transport *);
extern void udp_report (struct transport *);
extern int udp_fd_set (struct transport *, fd_set *, int);
extern int udp_fd_isset (struct transport *, fd_set *);
static void rekey_udp_handle_message (struct transport *);
static int rekey_udp_send_message (struct message *);
extern void udp_get_dst (struct transport *, struct sockaddr **, int *);
extern void udp_get_src (struct transport *, struct sockaddr **, int *);
extern char *udp_decode_ids (struct transport *);
extern void exchange_enter (struct exchange *);

static int initiator_send_SEQ_SA_KD_SIG (struct message *);
static int responder_recv_SEQ_SA_KD_SIG (struct message *);

struct spi_proto_arg {
  u_int32_t spi;
  u_int8_t proto;
};

int (*gdoi_rekey_initiator[]) (struct message *) = {
  initiator_send_SEQ_SA_KD_SIG,
};

int (*gdoi_rekey_responder[]) (struct message *) = {
  responder_recv_SEQ_SA_KD_SIG,
};

static struct transport_vtbl rekey_udp_transport_vtbl = {
  { 0 }, "rekey_udp",
  rekey_udp_create,
  udp_remove,
  udp_report,
  udp_fd_set,
  udp_fd_isset,
  rekey_udp_handle_message,
  rekey_udp_send_message,
  udp_get_dst,
  udp_get_src,
  udp_decode_ids
};

enum roles {
  SENDER,
  RECEIVER,
};

extern int compare_ids(u_int8_t *, u_int8_t *, size_t);
static struct transport *rekey_udp_make (struct gdoi_kek *, enum roles);
struct exchange *exchange_create (int, int, int, int);


TAILQ_HEAD (gdoi_kek_head, gdoi_kek) gdoi_kek_queue;

void
gdoi_rekey_init (void)
{
  transport_method_add (&rekey_udp_transport_vtbl);
  TAILQ_INIT (&gdoi_kek_queue);
}

struct gdoi_kek *
gdoi_get_kek (u_int8_t *id, size_t id_len, int create)
{
  struct gdoi_kek *node;

  /*
   * Sanity check
   */
  if (!id)
    {
	  log_print("gdoi_get_kek: No identity payload!");
	  return 0;
	}

  for (node = TAILQ_FIRST (&gdoi_kek_queue); node;
	   node = TAILQ_NEXT (node, link))
	{
	  if (compare_ids(id, node->group_id, node->group_id_len) == 0)
	  	{
			break;
		}
	}

  if (!node && create)
  	{
	  node = calloc(1, sizeof(struct gdoi_kek));
	  if (!node)
	  	{
		  return 0;
		}
	  node->group_id_len = id_len;
	  node->group_id = malloc(id_len);
	  if (!node->group_id)
	  	{
		  free(node);
		  return 0;
		}
	  TAILQ_INIT(&node->deleted_sa_list);
	  memcpy(node->group_id, id, id_len);
	  TAILQ_INSERT_TAIL (&gdoi_kek_queue, node, link);
	}

  return node;
}

struct gdoi_kek *
gdoi_get_kek_by_cookies (u_int8_t *cookies)
{
  struct gdoi_kek *node;

  for (node = TAILQ_FIRST (&gdoi_kek_queue); node;
	   node = TAILQ_NEXT (node, link))
	{
	  if (strncmp((char *)cookies, (char *)node->spi, KEK_SPI_SIZE) == 0)
	  	{
			return node;
		}
	}

  return NULL;
}

struct gdoi_kek *
gdoi_get_kek_by_transport (struct transport *transport)
{
  struct gdoi_kek *node;

  for (node = TAILQ_FIRST (&gdoi_kek_queue); node;
	   node = TAILQ_NEXT (node, link))
	{
	  if (transport == node->send_transport)
	  	{
			return node;
		}
	}

  return NULL;
}

struct gdoi_kek *
gdoi_get_kek_by_name (char *name)
{
  struct gdoi_kek *node;

  if (!name)
	{
	  return NULL;
	}

  for (node = TAILQ_FIRST (&gdoi_kek_queue); node;
	   node = TAILQ_NEXT (node, link))
	{
	  if (node->exchange_name && !strcmp(name, node->exchange_name))
	  	{
		  return node;
		}
	}

  return NULL;
}

/*
 * Sender side only
 * Open a socket to the multicast group for the purposes of joining the
 * group. Then open the socket with which to send rekey messages to the 
 * multicast group. They must be unique.
 */
static int
gdoi_rekey_open_socket (struct gdoi_kek *kek, enum roles role)
{
  int *s;

  /*
   * Sanity check the rekey fields we're going to use
   */
  if ((kek->dst_addr == INADDR_NONE) || (kek->src_addr == INADDR_NONE))
  	{
	  log_error("gdoi_rekey_open_socket: No rekey address");
	  return -1;
	}
  if ((kek->dport == 0) || (kek->sport == 0))
  	{
	  log_error("gdoi_rekey_open_socket: No rekey port");
	  return -1;
	}

  if (role == SENDER)
  	{
	  s = &kek->send_sock;
  	  kek->send_addr.sin_family = PF_INET;
  	  kek->send_addr.sin_port = htons(kek->sport);
	  kek->send_addr.sin_addr.s_addr = kek->src_addr;
#ifndef USE_OLD_SOCKADDR
  	  kek->send_addr.sin_len = sizeof(struct sockaddr_in);
#endif
	}
  else
  	{
	  s = &kek->recv_sock;
  	  kek->recv_addr.sin_family = PF_INET;
  	  kek->recv_addr.sin_port = kek->dport; /* Leave in host order */ 
  	  kek->recv_addr.sin_addr.s_addr = kek->dst_addr;
#ifndef USE_OLD_SOCKADDR
  	  kek->recv_addr.sin_len = sizeof(struct sockaddr_in);
#endif
	}

  /*
   * Setup sending side socket
   */
  *s = socket (AF_INET, SOCK_DGRAM, 0);
  if (*s < 0)
  	{
	  log_error("gdoi_rekey_open_socket: Socket open failed");
	  return -1;
	}

  return 0;
}

static void
rekey_crypto_encrypt (struct keystate *ks, u_int8_t *buf, u_int16_t len)
{
  LOG_DBG_BUF ((LOG_CRYPTO, 10, "rekey_crypto_encrypt: before encryption", buf,
		len));
  ks->xf->encrypt (ks, buf, len);
  memcpy (ks->liv, buf + len - ks->xf->blocksize, ks->xf->blocksize);
  LOG_DBG_BUF ((LOG_CRYPTO, 30, "rekey_crypto_encrypt: after encryption", buf,
		len));
}

void
rekey_crypto_decrypt (struct keystate *ks, u_int8_t *buf, u_int16_t len)
{
  LOG_DBG_BUF ((LOG_CRYPTO, 10, "rekey_crypto_decrypt: before decryption", buf,
		len));
  memcpy (ks->liv, buf + len - ks->xf->blocksize, ks->xf->blocksize);
  ks->xf->decrypt (ks, buf, len);;
  LOG_DBG_BUF ((LOG_CRYPTO, 30, "rekey_crypto_decrypt: after decryption", buf,
		len));
}

/*
 * Encrypt an outgoing message MSG.  As outgoing messages are represented
 * with an iovec with one segment per payload, we need to coalesce them
 * into just une buffer containing all payloads and some padding before
 * we encrypt.
 */
static int
gdoi_rekey_message_encrypt (struct message *msg, struct gdoi_kek *stored_kek)
{
  struct exchange *exchange = msg->exchange;
  size_t sz = 0;
  u_int8_t *buf;
  int i;
  enum cryptoerr err;

  /* If no payloads, nothing to do.  */
  if (msg->iovlen == 1) {
    log_print ("gdoi_rekey_message_encrypt: No payloads to encrypt!");
    return -1;
  }

  /*
   * Setup the crypto vectors based on the algorithm. We have to translate
   * The GDOI algorithm number to the IKE one in order to use the crypto 
   * routines....
   */
  switch (stored_kek->encrypt_alg)
  {
  case GDOI_KEK_ALG_3DES:
    exchange->crypto = crypto_get(TRIPLEDES_CBC);
	break;
  case GDOI_KEK_ALG_AES:
    if (stored_kek->encrypt_key_len == AES128_LENGTH)
      {
    	exchange->crypto = crypto_get(AES_CBC_128);
      }
    else
      {
		log_error ("decode_kd_kek_attribute: Unsupported AES key length %d",
		    stored_kek->encrypt_key_len);
		return -1;
      }
    break;
  default:
    log_error ("decode_kd_kek_attribute: "
	       	   "Unknown KEK secrecy algorithm: %d", stored_kek->encrypt_alg);
	return -1;
  }
  exchange->keystate = crypto_init (exchange->crypto, stored_kek->encrypt_key, 
  									exchange->crypto->keymax, &err);
  /*
   * RFC 3547 specifies a static IV for the rekey. It is unfortuanate, but
   * there isn't an easy placae to insert a dynamic IV into the ISAKMP header. 
   * Re-install the static IV into the crypto state each time we do an 
   * encryption.
   */
   crypto_init_iv (exchange->keystate, stored_kek->encrypt_iv,
   				   exchange->keystate->xf->blocksize);

  /*
   * For encryption we need to put all payloads together in a single buffer.
   * This buffer should be padded to the current crypto transform's blocksize.
   */
  for (i = 1; i < msg->iovlen; i++)
    sz += msg->iov[i].iov_len;
  sz = ((sz + exchange->crypto->blocksize - 1) / exchange->crypto->blocksize)
    * exchange->crypto->blocksize;
  buf = realloc (msg->iov[1].iov_base, sz);
  if (!buf)
    {
      log_error ("message_encrypt: realloc (%p, %d) failed",
		 msg->iov[1].iov_base, sz);
      return -1;
    }
  msg->iov[1].iov_base = buf;
  for (i = 2; i < msg->iovlen; i++)
    {
      memcpy (buf + msg->iov[1].iov_len, msg->iov[i].iov_base,
	      msg->iov[i].iov_len);
      msg->iov[1].iov_len += msg->iov[i].iov_len;
      free (msg->iov[i].iov_base);
    }

  /* Pad with zeroes.  */
  memset (buf + msg->iov[1].iov_len, '\0', sz - msg->iov[1].iov_len);
  msg->iov[1].iov_len = sz;
  msg->iovlen = 2;

  SET_ISAKMP_HDR_FLAGS (msg->iov[0].iov_base,
			GET_ISAKMP_HDR_FLAGS (msg->iov[0].iov_base)
			| ISAKMP_FLAGS_ENC);
  SET_ISAKMP_HDR_LENGTH (msg->iov[0].iov_base, ISAKMP_HDR_SZ + sz);
  rekey_crypto_encrypt (exchange->keystate, buf, msg->iov[1].iov_len);
  msg->flags |= MSG_ENCRYPTED;

  return 0;
}

/*
 * Read the keypair file and stuff it into the stored KEK suitable for
 * use with openssl.
 *
 * Also create a DER version of the public key (according to PKCS 2.0)
 * for sending to the group members.
 */
int gdoi_read_keypair (u_int8_t *infile, struct gdoi_kek *stored_kek)
{
    BIO *in=NULL, *out=NULL;
    BUF_MEM *buf_mem=NULL;

	/*
	 * Open the DER based key file and get the keypair.
	 */
    in = BIO_new (BIO_s_file());
    if (!in)
    {
      log_print ("gdoi_read_keypair: "
				 "BIO_new(BIO_s_file()) failed");
      return -1;
    }

    if (BIO_read_filename (in, infile) <= 0) 
	{
      log_print ("gdoi_read_keypair: "
				   "BIO_read_filename (in, \"%s\") failed",
				   infile);
	  BIO_free (in);
      return -1;
    }

    stored_kek->rsa_keypair = d2i_RSAPrivateKey_bio(in,NULL);
    if (!stored_kek->rsa_keypair)
	{
	  log_print ("gdoi_read_keypair: "
				 "d2i_RSAPrivateKey_bio failed");
	  BIO_free (in);
	  return -1;
	}

	BIO_free (in);

    /*
 	 * Now create a PKCS 2.0 version of the public key
	 */

    out = BIO_new (BIO_s_mem());

    if (!i2d_RSA_PUBKEY_bio(out,stored_kek->rsa_keypair))
    {
	  log_print ("gdoi_read_keypair: "
				 "i2d_RSA_PUBKEY_bio failed");
	  return -1;
	}

    BIO_get_mem_ptr(out, &buf_mem);

	stored_kek->signature_key_len = buf_mem->length;
	stored_kek->signature_key = calloc(1, stored_kek->signature_key_len);
	if (!stored_kek->signature_key)
	  {
      	log_error ("gdoi_get_kek_policy: "
	        	   "calloc failed (%d)", stored_kek->signature_key_len);
		BIO_free (out);
	    return -1;
	  }

	memcpy(stored_kek->signature_key, buf_mem->data, 
	  		 stored_kek->signature_key_len);
    stored_kek->signature_key_modulus_size = 
			BN_num_bits(stored_kek->rsa_keypair->n);
	BIO_free (out);
    return 0; 
}

int gdoi_store_pubkey (u_int8_t *der, int der_len, struct gdoi_kek *stored_kek)
{
    BIO *in=NULL;
    BUF_MEM *buf_mem;
	u_int8_t *der_copy;

	/*
	 * Only support RSA for now.
	 */
    if (stored_kek->sig_alg != GDOI_KEK_SIG_ALG_RSA)
      {
	  	log_print ("gdoi_store_keypair: Unsupported signature algorithm!");
	  	return -1;
      }
    
	in = BIO_new (BIO_s_mem());

    buf_mem = malloc(sizeof(BUF_MEM));
	if (!buf_mem)
	  {
      	log_error ("gdoi_store_pubkey: "
	        	   "malloc failed (%d)", sizeof(BUF_MEM));
		return -1;
	  }
    der_copy = malloc(der_len);
	if (!der_copy)
	  {
      	log_error ("gdoi_store_pubkey: "
	        	   "malloc failed (%d)", der_len);
	  	BIO_free (in);
		return -1;
	  }
    memcpy(der_copy, der, der_len);
	buf_mem->data = (char *)der_copy;
	buf_mem->length = der_len;
	buf_mem->max = der_len;
	BIO_set_mem_buf(in, buf_mem, der_len);
  
    /*
	 * Store the public key in the stored_kek. This is not really a
	 * "keypair", but we're re-using the key server structure so it's
	 * named oddly.
	 */
    stored_kek->rsa_keypair = d2i_RSA_PUBKEY_bio(in,NULL);
	if (!stored_kek->rsa_keypair)
    {
	  log_print ("gdoi_store_keypair: "
		 		 "d2i_RSA_PUBKEY_bio failed");
	  BIO_free (in);
	  free(der_copy);
	  return -1;
    }

    /*
     * Validate that the size of the keypair matches what we were told in
     * the SA payload.
     */
  	if (BN_num_bits(stored_kek->rsa_keypair->n) != 
	  	stored_kek->signature_key_modulus_size)
	  {
	    log_print ("gdoi_store_pubkey: Modulus size of signature key "
			       "doesn't match the SA payload policy. Expected %d "
				   "got %d", stored_kek->signature_key_modulus_size,
				   BN_num_bits(stored_kek->rsa_keypair->n));
	    return -1;
	  }

	/*
	 * The mem_buf pointer (der_copy) seems to be freed as part of BIO_free.
	 */
	BIO_free (in);
	return 0;
}

extern int gdoi_add_sa_payload (struct message *);
extern int gdoi_add_kd_payload (struct message *);

static int gdoi_add_sig_payload (struct message *msg, 
								 struct gdoi_kek *stored_kek)
{
  struct hash *hash;
  u_int8_t *buf;
  u_int32_t datalen = 0, sig_bytes;
  u_int8_t hdr[ISAKMP_HDR_SZ];
  int i;
  char header[80];
  u_int8_t *data;

  /*
   * Calculate the hash over the "rekey" prefix, IKE header, and payloads.
   */
  hash = hash_get(xlate_gdoi_hash(stored_kek->sig_hash_alg));
  buf = malloc (hash->hashsize);
  if (!buf)
	{
	  log_error ("gdoi_add_sig_payload: "
	  			 "malloc (%d) failed", hash->hashsize);
	}

  /* Start with the characters in 'rekey' */
  hash->Init (hash->ctx);
  LOG_DBG_BUF ((LOG_MISC, 90, "gdoi_add_sig_payload: 'rekey'", 
  				(u_int8_t *)REKEY_HEADER_STRING, strlen(REKEY_HEADER_STRING)));
  hash->Update (hash->ctx, (u_int8_t *)REKEY_HEADER_STRING, 
		  					strlen(REKEY_HEADER_STRING));

  /*
   * The header must be adjusted in the following ways in order to match
   * what the receiver will be hashing:
   *   1) The length must include the size of the SIG payload. The size of the 
   *      SIG payload will be the size of the modulus + 4 bytes for the SIG 
   *      payload header.
   *   2) The encrypted bit will be enabled.
   */
  if (msg->iov[0].iov_len != ISAKMP_HDR_SZ)
   	{
	  log_print("gdoi_add_sig_payload: GDOI header length incorrect");
	  return -1;
	}
  memcpy(hdr, msg->iov[0].iov_base, ISAKMP_HDR_SZ);

  /* 
   * Adjust the length 
   */
  sig_bytes = (BN_num_bits(stored_kek->rsa_keypair->n) / 8) + ISAKMP_GEN_SZ;
  SET_ISAKMP_HDR_LENGTH(hdr, GET_ISAKMP_HDR_LENGTH(hdr) + sig_bytes);
  /* 
   * Fix the encrypted bit 
   */
  SET_ISAKMP_HDR_FLAGS (hdr, GET_ISAKMP_HDR_FLAGS (hdr) | ISAKMP_FLAGS_ENC);

  LOG_DBG_BUF ((LOG_MISC, 90, "gdoi_add_sig_payload: 'ISAKMP header'", 
  				hdr, ISAKMP_HDR_SZ));
  hash->Update (hash->ctx, hdr, ISAKMP_HDR_SZ);

  /* Loop over all payloads including the HDR.  */
  for (i = 1; i < msg->iovlen; i++)
    {
	  snprintf (header, 80, "gdoi_add_sig_payload: payload %d",
	                  i);
      LOG_DBG_BUF ((LOG_MISC, 90, header, 
	  		msg->iov[i].iov_base, msg->iov[i].iov_len));
      hash->Update (hash->ctx, msg->iov[i].iov_base, msg->iov[i].iov_len);
    }

  hash->Final (buf, hash->ctx);
  LOG_DBG_BUF ((LOG_NEGOTIATION, 80,
	  			"gdoi_add_sig_payload: computed hash", buf, hash->hashsize));

  /* 
   * Sign the packet following the model in rsa_sig_encode_hash() 
   */
  if (!stored_kek->rsa_keypair)
  	{
	  log_print("gdoi_add_sig_payload: No private key found!");
	  return -1;
	}

  data = malloc (sig_bytes);
  if (!data)
    {
      log_error ("gdoi_add_sig_payload: malloc (%d) failed",
		 RSA_size (stored_kek->rsa_keypair));
      return -1;
    }

  /*
   * The signing parameters aren't well specified in the GDOI draft. There
   * are several PKCS#1 v2.0 parameters for padding. Here we've chosen
   * the one named "EMSA-PKCS1-v1_5" in PKCS#1 v2.
   */
  datalen = RSA_private_encrypt (hash->hashsize, buf, (data+ISAKMP_SIG_SZ), 
				 stored_kek->rsa_keypair, RSA_PKCS1_PADDING);
  
  if (datalen != (BN_num_bits(stored_kek->rsa_keypair->n) / 8))
  	{
		log_error ("gdoi_add_sig_payload: signing failed");
	}

  if (message_add_payload (msg, ISAKMP_PAYLOAD_SIG, data, sig_bytes, 1)) 
    {
		free(data);
		return -1;
	}

  return 0;
}

/*
 * Check if SA matches what we are asking for through V_ARG.  It has to
 * be a finished phase 2 SA.
 * Modelled after ipsec_sa_check.
 *
 * Note that for GDOI we don't have a "destination" to compare against, simply
 * a SPI and protocol. This is accordance with RFC 4301 where the SA lookup is
 * simply {SPI, protocol}.
 */
static int
gdoi_sa_check (struct sa *sa, void *v_arg)
{
  struct spi_proto_arg *arg = v_arg;
  struct proto *proto;

  if (sa->phase != 2 || !(sa->flags & SA_FLAG_READY))
    return 0;

  for (proto = TAILQ_FIRST (&sa->protos); proto;
       proto = TAILQ_NEXT (proto, link))
    if ((arg->proto == 0 || proto->proto == arg->proto)
       && memcmp (proto->spi[0], &arg->spi, sizeof arg->spi) == 0)
      return 1;
  return 0;
}

/* 
 * Find an SA with a "name" of SPI & PROTO.  
 * Modelled after ipsec_sa_lookup
 * */
struct sa *
gdoi_sa_lookup (u_int32_t spi, u_int8_t proto)
{
  struct spi_proto_arg arg = { spi, proto };

  return sa_find (gdoi_sa_check, &arg);
}

/*
 * delete all SA's from addr with the associated proto and SPI's
 * Modeled after ispec_delete_spi_list.
 *
 * spis[] is an array of SPIs of size 16-octet for proto ISAKMP
 * or 4-octet otherwise.
 */
static void
gdoi_delete_spi_list (struct sockaddr *addr, u_int8_t proto, 
                       u_int8_t *spis, int nspis, char *type)
{
  struct sa *sa;
  int i;

  for (i = 0; i < nspis; i++) 
    {
      if (proto == ISAKMP_PROTO_ISAKMP)
        {
          u_int8_t *spi = spis + i * ISAKMP_HDR_COOKIES_LEN;

          sa = sa_lookup_isakmp_sa (addr, spi);
      	  if (sa == NULL)
            {
			  LOG_DBG ((LOG_SA, 30, "ipsec_delete_spi_list: "
		   				"could not locate IKE SA (SPI %08x, proto %u)",
		   				spi, proto));
	  		  continue;
			}
        } 
      else
        {
          u_int32_t spi = ((u_int32_t *)spis)[i];

          sa = gdoi_sa_lookup (spi, proto);
      	  if (sa == NULL)
            {
			  LOG_DBG ((LOG_SA, 30, "ipsec_delete_spi_list: "
		   				"could not locate IPsec SA (SPI %04x, proto %u)",
		   				ntohl(spi), proto));
	  		  continue;
			}
        }

      /* Delete the SA and search for the next */
      LOG_DBG ((LOG_SA, 30, "ipsec_delete_spi_list: "
	       "%s made us delete SA %p (%d references) for proto %d",
	       type, sa, sa->refcnt, proto));

      sa_free (sa);
    }
}
/*
 * Look for an deleted SA in the given group that matches  a particular
 * DOI and protocol type. (Protocol_type can be 0 for "no protocol".)
 */
static struct deleted_sa *find_deleted_sa (struct gdoi_kek *stored_kek,
										   u_int32_t doi, 
										   u_int8_t protocol_type)
{
  struct deleted_sa *del_sa;

  for(del_sa = TAILQ_FIRST (&stored_kek->deleted_sa_list); del_sa;
	  del_sa = TAILQ_NEXT (del_sa, link))
    {
		if ((del_sa->doi == doi) && (del_sa->protocol_type == protocol_type))
		  {
			return del_sa;
		  }
	}

  /*
   * No matching SAs found.
   */
  return NULL;
}

/*
 * Add a delete payload, if there are deleted SAs matching  the DOI & protocol
 * id.
 * Return values:
 *    -1 = error
 *     0 = no delete payloads added
 *     1 = delete payloads added
 */
static int
gdoi_create_delete_payload(struct message *msg, struct gdoi_kek *stored_kek, 
						   u_int32_t doi, u_int8_t protocol_type, 
						   size_t spi_sz)
{
  int spi_count = 0;
  u_int8_t *buf;
  struct deleted_sa *del_sa;
  size_t sz;

  if (!find_deleted_sa(stored_kek, doi,  protocol_type))
	{
	  return 0;
	}

	/*
     * Allocate the DELETE header
	 */
	sz = ISAKMP_DELETE_SZ; /* Allocate the DELETE header */
  	buf = malloc(sz);
  	if (!buf)
      {
	   log_error ("gdoi_add_delete_payload: Malloc of DELETE hdr failed");
	   return -1;
	  }

	/*
     * Setup as much header as possible
     */
    SET_ISAKMP_DELETE_DOI (buf, GROUP_DOI_GDOI);
	SET_ISAKMP_DELETE_PROTO (buf, protocol_type);
	SET_ISAKMP_DELETE_SPI_SZ (buf, spi_sz);

	while ((del_sa = find_deleted_sa(stored_kek, doi, protocol_type)))
    {
	  sz += spi_sz;
	  buf = realloc(buf, sz);
	  if (!buf)
		{
	  	  log_error ("gdoi_add_delete_payload: Realloc of %d failed", sz);
	  	  return -1;
		}
	  memcpy(buf+sz-spi_sz, del_sa->spi, spi_sz);
	  TAILQ_REMOVE (&stored_kek->deleted_sa_list, del_sa, link);
  	  free(del_sa);
	  spi_count++;
	}

	SET_ISAKMP_DELETE_NSPIS(buf, spi_count);

  	if (message_add_payload (msg, ISAKMP_PAYLOAD_DELETE, buf, sz, 1)) {
		free(buf);
		return -1;
	}

	return 1;
}

/*
 * This function may actually create several different DELETE paylaods:
 * a) One payload per DOI is required (i.e., GDOI TEKs, GDOI Rekey SA)
 * b) If within the GDOI TEKs there are multiple Protocols (e.g., AH/ESP),
 *    there must be a unique payload per Protocol ID.
 * Therefore, if a KEK SPI, ESP SPI, and AH SPI are all deleted this will
 * result in 3 DELETE paylaods.
 */
static int
gdoi_add_delete_payloads(struct message *msg, struct gdoi_kek *stored_kek,
						 int *added)
{
  int ret;

  /*
   * Deleted ESP SAs
   */
  ret = gdoi_create_delete_payload(msg, stored_kek, GROUP_DOI_GDOI, 
		  					 	   GDOI_TEK_PROT_PROTO_IPSEC_ESP, 4);
  if (ret < 0) return -1;
  if (ret == 1) *added += 1;

  /*
   * Deleted AH SAs
   */
  ret = gdoi_create_delete_payload(msg, stored_kek, GROUP_DOI_GDOI, 
		  					 GDOI_TEK_PROT_PROTO_IPSEC_AH, 4);
  if (ret < 0) return -1;
  if (ret == 1) *added +=1;
  
  /*
   * Deleted KEK SAs
   */
  ret = gdoi_create_delete_payload(msg, stored_kek, ISAKMP_DOI_ISAKMP, 0, 
		  						   KEK_SPI_SIZE);
  if (ret < 0) return -1;
  if (ret == 1) *added +=1;
  
  return 0;
}

/*
 * Handle a delete payload.
 * Extracted from ipsec_handle_leftover_payload().
 */
int
gdoi_process_delete_payload (struct message *msg, struct payload *payload)
{
  u_int32_t spisz, nspis;
  struct sockaddr *dst;
  socklen_t dstlen;
  u_int8_t *spis, proto, ipsec_proto;

  proto = GET_ISAKMP_DELETE_PROTO (payload->p);
  nspis = GET_ISAKMP_DELETE_NSPIS (payload->p);
  spisz = GET_ISAKMP_DELETE_SPI_SZ (payload->p);

  payload->flags |= PL_MARK;

  if (nspis == 0)
  	{
	  LOG_DBG ((LOG_SA, 60, "gdoi_process_delete_payload: message "
		    "specified zero SPIs, ignoring"));
	  return -1;
	}

  /* verify proper SPI size */
  switch (proto)
    {
	  case GDOI_TEK_PROT_PROTO_IPSEC_ESP:
	  case GDOI_TEK_PROT_PROTO_IPSEC_AH:
	  	if (spisz != sizeof (u_int32_t))
		  {
	  		log_print ("gdoi_process_delete_payload: invalid IPsec SPI size %d"
					   " for proto %d in DELETE payload", spisz, proto);
			return -1;
		  }
		  break;
	  case ISAKMP_DOI_ISAKMP:
	  	if (spisz != ISAKMP_HDR_COOKIES_LEN) 
		  {
	  		log_print ("gdoi_process_delete_payload: "
		     		   "invalid IKE SPI size %d for proto %d in DELETE payload",
		     		   spisz, proto);
			return -1;
		  }
		  break;
	  default:
	  	log_print ("gdoi_process_delete_payload: "
	     		   "Unknown proto %d in DELETE payload", proto);
		return -1;
	}

  spis = (u_int8_t *)malloc (nspis * spisz);
  if (!spis)
    {
 	  log_error ("gdoi_process_delete_payload: malloc (%d) failed",
	     		 nspis * spisz);
	  return -1;
	}

  /* extract SPI and get dst address */
  memcpy (spis, payload->p + ISAKMP_DELETE_SPI_OFF, nspis * spisz);
  msg->transport->vtbl->get_dst (msg->transport, &dst, (int *)&dstlen);

  /* need to convert GDOI proto to IPsec proto ID */
  switch (proto)
    {
	  case GDOI_TEK_PROT_PROTO_IPSEC_ESP:
	  	ipsec_proto = IPSEC_PROTO_IPSEC_ESP;
		break;
	  case GDOI_TEK_PROT_PROTO_IPSEC_AH:
	  	ipsec_proto = IPSEC_PROTO_IPSEC_AH;
		break;
	  case ISAKMP_DOI_ISAKMP:
	  default: /* did error checking above */
	  	ipsec_proto = proto;
	  	break;
	}
  gdoi_delete_spi_list (dst, ipsec_proto, spis, nspis, "DELETE");

  free (spis);

  return 0;
}

/*
 * The current hardcoded policy for rekey is to send new SPIs and keys for 
 * orginal policy in the configuration file. To do that, we use the same code 
 * as the registration message to get the SAs, expect the behavior for the
 * SPIs and keys is different.
 */
static int
initiator_send_SEQ_SA_KD_SIG (struct message *msg)
{
  struct payload *p;
  struct gdoi_kek *stored_kek;
  u_int8_t *seq_buf = 0;
  size_t sz;
  int have_delete_payloads = 0;

  /*
   * Find the KEK. The only search value we have is the transport address,
   * which is fixed in the KEK, and installed in the msg by the GDOI message
   * initiating logic.
   */
  stored_kek = gdoi_get_kek_by_transport(msg->transport);
  if (!stored_kek)
    {
      log_print ("initiator_send_SEQ_SA_KD_SIG: SA not found in rekey SA list");
	  return -1;
	}

  /*
   * Add SEQ payload with the current sequence number & then increment it for
   * the next time.
   */
  sz = GDOI_SEQ_SEQ_NUM_OFF + GDOI_SEQ_SEQ_NUM_LEN;
  seq_buf = calloc (1, sz);
  if (!seq_buf)
	{
      log_error ("initiator_send_SEQ_SA_KD_SIG: calloc (%d) failed", sz);
      goto bail_out;
	}
  /*
   * The reciever will check that the next one is greater than the value sent
   * in the registration message. Therefore we must increment the seq value
   * BEFORE sending it in this message.
   */
  stored_kek->current_seq_num++;
  SET_GDOI_SEQ_SEQ_NUM(seq_buf, stored_kek->current_seq_num);
  log_print ("SENT SEQ # of: %d (PUSH)", stored_kek->current_seq_num);
  if (message_add_payload (msg, ISAKMP_PAYLOAD_SEQ, seq_buf, sz, 1)) {
    return -1;
  }

  if (gdoi_add_delete_payloads(msg, stored_kek, &have_delete_payloads)) {
 	  return -1;
    }

  /*
   * Don't send SA/KD payloads if we're just cleaning up the group.
   */
  if ((stored_kek->flags & CLEANING_UP))
    {
	  if (!have_delete_payloads)
	  	{
			log_print ("initiator_send_SEQ_SA_KD_SIG: Cleaning up, but no"
					   " delete payloads found. Aborting - Nothing to do.");
			return -1;
		}

      /*
       * Fixup the last DELETE payload "next payload" so that the hash of the
       * DELETE payload is correct. This needs to be set before going to
       * the signature code.
       */
      p = TAILQ_LAST (&msg->payload[ISAKMP_PAYLOAD_DELETE], payload_head);
      if (!p)
  		{
	  	  log_print("initiator_send_SEQ_SA_KD_SIG: DELETE payload missing");
	  	  return -1;
		}
      SET_ISAKMP_GEN_NEXT_PAYLOAD(p->p, ISAKMP_PAYLOAD_SIG);
    }
  else
    {
      /*
       * Add the SA payload from the config file. 
       */
      if (gdoi_add_sa_payload(msg)) {
 	  	return -1;
      }
  
      /*
       * Add the KD payload from the config file. 
       */
      if (gdoi_add_kd_payload(msg)) {
  	  	return -1;
      }

      /*
       * Fixup the KD payload "next payload" so that the hash of the KD
       * payload is correct. This needs to be set before going to the
       * signature code.
       */
      p = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_KD]);
      if (!p)
  		{
	  	  log_print("initiator_send_SEQ_SA_KD_SIG: KD payload missing");
	  	  return -1;
		}
      SET_ISAKMP_GEN_NEXT_PAYLOAD(p->p, ISAKMP_PAYLOAD_SIG);
  }

  /*
   * Add the SIG payload and sign it.
   */
  if (gdoi_add_sig_payload(msg, stored_kek)) {
  	return -1;
  }

  if (gdoi_rekey_message_encrypt(msg, stored_kek)) {
	return -1;
  }

  return 0;

bail_out:
  if (seq_buf) {
	  free(seq_buf);
	}
  return -1;
}

int
gdoi_rekey_setup_exchange (struct gdoi_kek *kek)
{
  struct gdoi_exch *ie;

  kek->send_exchange = 
  	exchange_create (1, 0, GROUP_DOI_GDOI, GDOI_EXCH_PUSH_MODE);
  if (!kek->send_exchange)
  	{
	  log_print("gdoi_rekey_setup_exchange: exchange creation failed");
	  return -1;
	}
   memcpy (kek->send_exchange->cookies, kek->spi, ISAKMP_HDR_COOKIES_LEN);
   ie = kek->send_exchange->data;
   ie->id_gdoi_sz = kek->group_id_len;
   ie->id_gdoi = calloc (1, ie->id_gdoi_sz);
   memcpy(ie->id_gdoi, kek->group_id, ie->id_gdoi_sz);
   kek->send_exchange->initiator = 1;
   exchange_enter (kek->send_exchange);
   TAILQ_INIT(&ie->spis);
   return 0;
}

/*
 * Delete an SA from the list, and insert it on the KEK deleted SA list.
 */
int
gdoi_add_deleted_sa (struct gdoi_kek *kek, struct sa *sa)
{
	struct proto *proto;
	struct deleted_sa *del_sa;

	proto = TAILQ_FIRST (&sa->protos);
	if (!proto)
	  {
		log_print("gdoi_add_deleted_sa: No proto found for SA %#x", sa);
		return -1;
	  }
		
	log_print("gdoi_add_deleted_sa: Deleting SPI (SA) %u (%d) (%#x) for sa %#x",
			  decode_32(proto->spi[0]), decode_32(proto->spi[0]), 
			  decode_32(proto->spi[0]), sa);

	del_sa = malloc(sizeof(struct deleted_sa));
	if (!del_sa)
	  {
		log_print("gdoi_add_deleted_sa: deleted SA malloc failure");
		return -1;
	  }
	/*
	 * RFC 3547 says the DOI must be GDOI except for a KEK SPI, which
	 * must be zero. Protocol IDs within the GDOI DOI come from Section 5.4 of
	 * RFC 3547.
	 */
	del_sa->doi = GROUP_DOI_GDOI;
	/*
	 * Insert the SPIs in network byte order. This is the last convenient
	 * place to know what size the SPI should be by protocol type.
	 */
	switch (proto->proto)
	  {
		  case IPSEC_PROTO_IPSEC_ESP:
		 	del_sa->protocol_type = GDOI_TEK_PROT_PROTO_IPSEC_ESP;
			if (proto->spi_sz[0] != 4)
			  {
				log_error("gdoi_add_deleted_sa: Wrong ESP SPI size %d",
					  proto->spi_sz[0]);
				return -1;
			  }
			memcpy(del_sa->spi, proto->spi[0], proto->spi_sz[0]);
			break;
		  case IPSEC_PROTO_IPSEC_AH:
		 	del_sa->protocol_type = GDOI_TEK_PROT_PROTO_IPSEC_AH;
			if (proto->spi_sz[0] != 4)
			  {
				log_error("gdoi_add_deleted_sa: Wrong AH SPI size %d",
					  proto->spi_sz[0]);
				return -1;
			  }
			memcpy(del_sa->spi, proto->spi[0], proto->spi_sz[0]);
			break;
		  default:
			log_error("gdoi_add_deleted_sa: Unsupported protocol %d",
					  proto->proto);
			free(del_sa);
			return -1;
	  }
	TAILQ_INSERT_TAIL (&kek->deleted_sa_list, del_sa, link);
	sa_free(sa);

	return 0;
}

static int
gdoi_rekey_send_msg (struct gdoi_kek *kek)
{
  struct message *msg;

  if (!kek->send_sock)
    {
	  /*
	   * Open a socket for sending
	   */
	  if (gdoi_rekey_open_socket(kek, SENDER) <0)
	  	{
		  log_print("gdoi_rekey_send_msg: Socket open failed");
		  return -1;
		}
    }
  if (!kek->send_transport)
    {
      kek->send_transport = rekey_udp_make (kek, SENDER);
	  if (!kek->send_transport)
	  	{
		  log_print("gdoi_rekey_send_msg: transport creation failed");
		  return -1;
		}
	}
  if (!kek->send_exchange)
    {
	  if (gdoi_rekey_setup_exchange(kek))
	  	{
		  return -1;
		}
	}
  else
  	{
	  /*
	   * Reset the exchange "PC" to the beginning. This is necssary because
	   * we're re-using the exchange structure for each rekey so that we can
	   * accumulate SAs in one exchange.
	   *
	   * This assumes that we are never working on more than 1 rekey message
	   * for a particular group at any one time ....
	   */
	  kek->send_exchange->exch_pc = (int16_t *)exchange_script (kek->send_exchange);
	  kek->send_exchange->step = 0;
	}
  msg = message_alloc (kek->send_transport, 0, ISAKMP_HDR_SZ);
  msg->exchange = kek->send_exchange;
  message_setup_header (msg, GDOI_EXCH_PUSH_MODE, ISAKMP_FLAGS_ENC, 
					    kek->send_exchange->message_id);
  exchange_run (msg);
  return 0;
}

/*
 * Delete GDOI SAs and send a rekey with delete payloads & new SAs matching
 * the policy.
 *
 * Called from receiving a TERM signal.
 *
 * NOTE: If the group has no KEK (i.e., no rekey) then there is no point in
 * "deleting" the SAs because we can't send a rekey anyway. Therefore, this
 * code does not deal with group which have no rekey.
 */
void gdoi_rekey_delete_sas (fd_set *wfds)
{
  struct gdoi_kek *kek;
  struct sa *sa;

  for (kek = TAILQ_FIRST(&gdoi_kek_queue); kek;
	   kek = TAILQ_NEXT (kek, link))
    {
	  if (!kek->send_exchange)
		{
		  /*
		   * Not a key server for this group.
		   */
		  continue;
		}
  	  log_print("gdoi_rekey_delete_sas: Deleting SAs and Sending a rekey "
		    "with DELETE paylaods for exchange %s",
			(kek->exchange_name ? kek->exchange_name : "unknown"));
	  /*
	   * Find the TEKs associated with the rekey exchange.
	   */
	  sa = TAILQ_FIRST (&kek->send_exchange->sa_list);
	  while (sa)
	  	{
		  gdoi_add_deleted_sa(kek, sa);
		  LOG_DBG ((LOG_SA, 60, "gdoi_rekey_delete_sas: "
							 "freeing SA %p from exchange %p", 
							 sa, kek->send_exchange));
		  sa_release(sa);
		  sa = TAILQ_NEXT (sa, next);
	    }
	  kek->flags |= CLEANING_UP;
	  gdoi_rekey_send_msg(kek);
	  udp_fd_set(kek->send_transport, wfds, 1);
   }

	return;
}

static void
gdoi_kek_rekey_sender (void *vkek)
{
  struct gdoi_kek *kek = vkek;

  log_print("gdoi_kek_rekey_sender: Timer sprung!!!");
  /*
   * Careful! Need to generate a rekey message using the OLD KEK keys, but
   * delivering the NEW key keys. 
   *
   * TODO: We should re-transmit this a couple of times in case of packet loss.
   * If we send it once and a device misses it, it won't be able to decrypt
   * future KEKs and will be forced to re-register.
   *
   * Using seperate flags for creating and sending a new KEK allows us to
   * later do re-transmits of the new KEK info.
   */
  kek->flags |= CREATE_NEW_KEK|SEND_NEW_KEK;
  if (gdoi_rekey_send_msg (kek) < 0)
  	{
  	  log_print("gdoi_rekey_sender: Error in sending msg - Aborting");
	  return;
	}
  gdoi_kek_rekey_start (kek);
  /*
   * Clean up flags
   */
  kek->flags &= ~(CREATE_NEW_KEK|SEND_NEW_KEK);
  /*
   * Install the new SPI and clean up.
   */
  memcpy(kek->spi, &kek->next_kek_policy.spi, KEK_SPI_SIZE);
  memset(&kek->next_kek_policy.spi, 0, KEK_SPI_SIZE);
  /*
   * Install the new SPI in the rekey exchange cookies too! However, the
   * exchange needs to be re-linked in the echange data structures.
   */
  memcpy(kek->send_exchange->cookies, &kek->spi, ISAKMP_HDR_COOKIES_LEN);
  LIST_REMOVE (kek->send_exchange, link);
  exchange_enter (kek->send_exchange);
  /*
   * Install the new keys and free old ones.
   */
  kek->encrypt_iv = kek->next_kek_policy.encrypt_iv;
  kek->encrypt_key = kek->next_kek_policy.encrypt_key;
  kek->next_kek_policy.encrypt_iv = NULL;
  kek->next_kek_policy.encrypt_key = NULL;
}

int
gdoi_kek_rekey_start (struct gdoi_kek *kek)
{
  struct timeval expire_time;

  gettimeofday (&expire_time, 0);
  expire_time.tv_sec += kek->kek_timer_interval;
  kek->tek_lifetime_ev = timer_add_event ("gdoi_kek_rekey_sender", 
		  			gdoi_kek_rekey_sender, kek, &expire_time);
  return 0;
}

static void
gdoi_rekey_sender (void *vkek)
{
  struct gdoi_kek *kek = vkek;

  log_print("gdoi_rekey_sender: Timer sprung!!!");
  gdoi_rekey_start (kek);
  if (gdoi_rekey_send_msg (kek) < 0)
  	{
  	  log_print("gdoi_rekey_sender: Error in sending msg - Aborting");
	  return;
	}
}

int
gdoi_rekey_start (struct gdoi_kek *kek)
{
  struct timeval expire_time;

  gettimeofday (&expire_time, 0);
  expire_time.tv_sec += kek->tek_timer_interval;
  kek->tek_lifetime_ev = timer_add_event ("gdoi_rekey_sender", 
		  			gdoi_rekey_sender, kek, &expire_time);
  return 0;
}

int
gdoi_rekey_listen (struct gdoi_kek *kek)
{
  if (kek->recv_sock)
    {
  	  log_print("gdoi_rekey_listen: Already a listener for this group.");
	  return 0;
	}

  log_print("gdoi_rekey_listen: Setting up rekey listener!");

  /*
   * Open a socket for receiving
   */
  if (gdoi_rekey_open_socket(kek, RECEIVER) <0)
  	{
	  log_print("gdoi_rekey_send_msg: Socket open failed");
	  return -1;
	}
  rekey_udp_make(kek, RECEIVER);
  return 0;
}

static struct transport *
rekey_udp_make (struct gdoi_kek *kek, enum roles role)
{
  int s;
  struct sockaddr_in *laddr;
  struct in_addr iaddr;
  u_int8_t ttl = IPDEFTTL;
  u_int8_t loop = 0; /* Disable loopback of our own multicast packets*/
  struct udp_transport *t = 0;
  int on;
  struct ip_mreq maddr;
  struct conf_list *listen_on;
  struct conf_list_node *address;

  t = calloc (1, sizeof *t);
  if (!t)
    {
      log_print ("rekey_udp_make: malloc (%d) failed", sizeof *t);
      return 0;
    }
  
  if (role == SENDER)
	{
  	  s = kek->send_sock;
  	  laddr = &kek->send_addr;
  	  t->dst.sin_family = PF_INET;
  	  t->dst.sin_port = htons(kek->dport);
  	  t->dst.sin_addr.s_addr = kek->dst_addr;
#ifndef USE_OLD_SOCKADDR
  	  t->dst.sin_len = sizeof(struct sockaddr_in);
#endif
	} 
  else
	{
  	  s = kek->recv_sock;
  	  laddr = &kek->recv_addr;
  	  t->dst.sin_family = PF_INET;
  	  t->dst.sin_port = kek->sport; 
  	  t->dst.sin_addr.s_addr = kek->src_addr;
#ifndef USE_OLD_SOCKADDR
  	  t->dst.sin_len = sizeof(struct sockaddr_in);
#endif
	} 

  /*
   * In order to have several bound specific address-port combinations
   * with the same port SO_REUSEADDR is needed.
   * If this is a wildcard socket and we are not listening there, but only
   * sending from it make sure it is entirely reuseable with SO_REUSEPORT.
   */
  on = 1;
  if (setsockopt (s, SOL_SOCKET,
		  (laddr->sin_addr.s_addr == INADDR_ANY
		   && conf_get_str ("General", "Listen-on"))
		  ? SO_REUSEPORT : SO_REUSEADDR,
		  (void *)&on, sizeof on) == -1)
    {
      log_error ("rekey_udp_make: setsockopt (%d, %d, %d, %p, %d)", s, SOL_SOCKET,
		 (laddr->sin_addr.s_addr == INADDR_ANY
		  && conf_get_str ("General", "Listen-on"))
		 ? SO_REUSEPORT : SO_REUSEADDR,
		 &on, sizeof on);
      goto err;
    }
  
  t->transport.vtbl = &rekey_udp_transport_vtbl;
  memcpy (&t->src, laddr, sizeof t->src);

  if (bind (s, (struct sockaddr *)&t->src, sizeof t->src))
   	{
   	  log_error ("rekey_udp_make: bind (%d, %p, %d)", s, &t->src, 
				 sizeof t->src);
   	  log_error("rekey_udp_make: Continuing anyway");
   	}

  if (role == RECEIVER)
  	{
	  if (IN_MULTICAST(htonl(laddr->sin_addr.s_addr)))
	    {
      	  bzero(&maddr, sizeof(maddr));
      	  maddr.imr_multiaddr.s_addr = laddr->sin_addr.s_addr;
		  /*
		   * Pick the first interface off the "Listen-on" list.
		   */
		  listen_on = conf_get_list ("General", "Listen-on");
	  	  if (listen_on)
	    	{
			  address = TAILQ_FIRST (&listen_on->fields);
	  	  	  if (!inet_aton (address->field, &iaddr))
	    		{
	      	  	  log_print ("rekey_udp_make: "
				  			 "invalid address %s in \"Listen-on\"",
			 			 	 address->field);
      	  	  	  goto err;
	    		}
      	  	  maddr.imr_interface.s_addr = iaddr.s_addr;
			}
      	  conf_free_list (listen_on);
      	  if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
		  				   &maddr,sizeof(maddr)))
		  	{
  			  log_error("rekey_udp_make: setsockopt(IP_ADD_MEMBERSHIP)");
      	  	  goto err;
      		}
		}
  	}

  if (role == SENDER)
    {
	  listen_on = conf_get_list ("General", "Listen-on");
	  if (listen_on)
	    {
      	  for (address = TAILQ_FIRST (&listen_on->fields); address;
	   		   address = TAILQ_NEXT (address, link))
			{
	  	  	  if (!inet_aton (address->field, &iaddr))
	    		{
	      	  	  log_print ("rekey_udp_make: "
				  			 "invalid address %s in \"Listen-on\"",
			 			 	 address->field);
      	  	  	  goto err;
	    		}
  	  	  	  if (setsockopt (s, IPPROTO_IP, IP_MULTICAST_IF, (void *)&iaddr, 
		  				  	  sizeof iaddr) == -1)
    			{
	      	  	  log_error ("rekey_udp_make: Setting IP_MULTICAST_IF failed");
      		  	  goto err;
    			}
  	  	  	  if (setsockopt (s, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&ttl, 
		  				  	  sizeof ttl) == -1)
    			{
	      	  	  log_error ("rekey_udp_make: Setting IP_MULTICAST_TTL failed");
      		  	  goto err;
    			}
  	  	  	  if (setsockopt (s, IPPROTO_IP, IP_MULTICAST_LOOP, (void *)&loop, 
		  				  	  sizeof loop) == -1)
    			{
	      	  	  log_error ("rekey_udp_make: Setting IP_MULTICAST_LOOP failed");
      		  	  goto err;
    			}
    		}
      	  conf_free_list (listen_on);
	    }
	}

  t->s = s;
  transport_add (&t->transport);
  transport_reference (&t->transport);
  t->transport.flags |= TRANSPORT_LISTEN;
  return &t->transport;

err:
  if (s != -1)
    close (s);
  if (t)
    free (t);
  return 0;
}

/*
 * Receive a rekey message. Based on message_recv().
 */
static int
rekey_message_recv (struct message *msg)
{
  u_int8_t *buf = msg->iov[0].iov_base;
  size_t sz = msg->iov[0].iov_len;
  int exch_type;
  u_int8_t flags;
  struct gdoi_kek *stored_kek;
  enum cryptoerr err;
  u_int8_t *cookies;
  struct sa *sa;

  /* Possibly dump a raw hex image of the message to the log channel.  */
  message_dump_raw ("message_recv", msg, LOG_MESSAGE);

  /* Messages shorter than an ISAKMP header are bad.  */
  if (sz < ISAKMP_HDR_SZ || sz != GET_ISAKMP_HDR_LENGTH (buf))
    {
      log_print ("message_recv: bad message length");
      message_drop (msg, ISAKMP_NOTIFY_UNEQUAL_PAYLOAD_LENGTHS, 0, 1, 1);
      return -1;
    }

  cookies = buf + ISAKMP_HDR_COOKIES_OFF;
  stored_kek = gdoi_get_kek_by_cookies (cookies);
  if (!stored_kek)
    {
      log_print ("rekey_message_recv: SA not found in rekey SA list");
      log_print ("rekey_message_recv: cookie pair:): "
  	    "%02x%02x%02x%02x%02x%02x%02x%02x "
	    "%02x%02x%02x%02x%02x%02x%02x%02x",
  	    cookies[0], cookies[1], cookies[2], cookies[3], cookies[4], 
	    cookies[5], cookies[6], cookies[7], cookies[8], cookies[9], 
	    cookies[10], cookies[11], cookies[12], cookies[13], cookies[14],
  	    cookies[15]);
	  return -1;
	}

  if (GET_ISAKMP_HDR_NEXT_PAYLOAD (buf) >= ISAKMP_PAYLOAD_PRIVATE_MAX)
    {
      log_print ("message_recv: "
		 "invalid payload type %d in ISAKMP header "
		 "(check passphrases, if applicable and in Phase 1)",
		 GET_ISAKMP_HDR_NEXT_PAYLOAD (buf));
      return -1;
    }

  /* Validate that the message is of version 1.0.  */
  if (ISAKMP_VERSION_MAJOR (GET_ISAKMP_HDR_VERSION (buf)) != 1)
    {
      log_print ("message_recv: invalid version major %d",
		 ISAKMP_VERSION_MAJOR (GET_ISAKMP_HDR_VERSION (buf)));
      return -1;
    }

  if (ISAKMP_VERSION_MINOR (GET_ISAKMP_HDR_VERSION (buf)) != 0)
    {
      log_print ("message_recv: invalid version minor %d",
		 ISAKMP_VERSION_MINOR (GET_ISAKMP_HDR_VERSION (buf)));
      return -1;
    }

  /*
   * Validate the exchange type.  It must be a rekey message type. If not,
   * ignore it.
   */
  exch_type = GET_ISAKMP_HDR_EXCH_TYPE (buf);
  if (exch_type != GDOI_EXCH_PUSH_MODE)
    {
      log_print ("message_recv: invalid exchange type %s",
		 constant_name (isakmp_exch_cst, exch_type));
      return -1;
    }
  msg->exchange = exchange_create (1, 0, GROUP_DOI_GDOI, exch_type);
  if (!msg->exchange)
    {
      log_print ("rekey_message_recv: failed to allocate exchange");
	  return -1;
	}

  /*
   * Save the cookies for later use in finding the stored KEK
   */
  memcpy(msg->exchange->cookies, cookies, ISAKMP_HDR_COOKIES_LEN);

  /*
   * Check for unrecognized flags. Only the encryption flag is valid for now.
   */
  flags = GET_ISAKMP_HDR_FLAGS (buf);
  if (flags != ISAKMP_FLAGS_ENC)
    {
      log_print ("rekey_message_recv: invalid flags 0x%x",
		 GET_ISAKMP_HDR_FLAGS (buf));
      return -1;
    }

  if (flags & ISAKMP_FLAGS_ENC)
    {
      msg->orig = malloc (sz);
      if (!msg->orig)
		{
	  	  message_free (msg);
	  	  return -1;
		}
      memcpy (msg->orig, buf, sz);

	  /*
	   * Setup the crypto vectors based on the algorithm. We have to translate
   	   * The GDOI algorithm number to the IKE one in order to use the crypto 
   	   * routines....
   	   */
  	  switch (stored_kek->encrypt_alg)
  		{
  		case GDOI_KEK_ALG_3DES:
    	  msg->exchange->crypto = crypto_get(TRIPLEDES_CBC);
		  break;
  		case GDOI_KEK_ALG_AES:
    	  msg->exchange->crypto = crypto_get(AES_CBC_128);
		  break;
  		default:
    	  log_error ("decode_kd_kek_attribute: "
	       	   		 "Unknown KEK secrecy algorithm: %d", 
					 stored_kek->encrypt_alg);
		  return -1;
  		}
  	  msg->exchange->keystate = crypto_init (msg->exchange->crypto, 
	  									stored_kek->encrypt_key, 
  										msg->exchange->crypto->keymax, &err);
  	  /*
   	   * Re-install the static IV into the crypto state
   	   * each time we do an encryption.
   	   */
   	  crypto_init_iv (msg->exchange->keystate, stored_kek->encrypt_iv,
   				   	  msg->exchange->keystate->xf->blocksize);

      rekey_crypto_decrypt (msg->exchange->keystate, buf + ISAKMP_HDR_SZ, 
	  						sz - ISAKMP_HDR_SZ);
    }
  else
    msg->orig = buf;
  msg->orig_sz = sz;

  /*
   * Check the overall payload structure at the same time as indexing them by
   * type.
   */
  if (GET_ISAKMP_HDR_NEXT_PAYLOAD (buf) != ISAKMP_PAYLOAD_NONE
      && message_sort_payloads (msg, GET_ISAKMP_HDR_NEXT_PAYLOAD (buf)))
    {
      return -1;
    }

  /*
   * Run generic payload tests now.  If anything fails these checks, the
   * message needs either to be retained for later duplicate checks or
   * freed entirely.
   * XXX Should SAs and even transports be cleaned up then too?
   */
  if (message_validate_payloads (msg))
    {
      return -1;
    }

  /*
   * HACK! message_validate_sa() Adds gratuitously create an SA payload for
   * us, but we don't need it. That SA payload is intended to be used as the
   sa->isakmp_sa but we don't need it for the rekey message. So remove it here.
   */
  sa = TAILQ_FIRST(&msg->exchange->sa_list);
  if (sa)
	{
  	  TAILQ_REMOVE(&msg->exchange->sa_list, sa, next);
  	  sa_release(sa);
  	  sa = NULL;
  }

  /*
   * Now we can validate DOI-specific exchange types.  If we have no SA
   * DOI-specific exchange types are definitely wrong.
   */
  if (exch_type >= ISAKMP_EXCH_DOI_MIN && exch_type <= ISAKMP_EXCH_DOI_MAX
      && msg->exchange->doi->validate_exchange (exch_type))
    {
      log_print ("message_recv: invalid DOI exchange type %d", exch_type);
      return -1;
    }

  /* Handle the flags.  */
  if (flags & ISAKMP_FLAGS_ENC)
    msg->exchange->flags |= EXCHANGE_FLAG_ENCRYPT;
  if ((msg->exchange->flags & EXCHANGE_FLAG_COMMITTED) == 0
      && (flags & ISAKMP_FLAGS_COMMIT))
    msg->exchange->flags |= EXCHANGE_FLAG_HE_COMMITTED;

  /* OK let the exchange logic do the rest.  */
  exchange_enter (msg->exchange);
  exchange_run (msg);

  return 0;
}

static struct transport *
rekey_udp_create (char *name)
{
  struct transport *t;
  struct udp_transport *u;

  t = malloc (sizeof *u);
  if (!t)
    {
      log_error ("rekey_udp_create: malloc (%d) failed", sizeof *u);
      return 0;
    }

  u = (struct udp_transport *)t;
  u->transport.vtbl = &rekey_udp_transport_vtbl;
  
  return t;
}

/*
 * A message has arrived on transport T's socket.  If T is single-ended,
 * clone it into a double-ended transport which we will use from now on.
 * Package the message as we want it and continue processing in the message
 * module.
 */
static void
rekey_udp_handle_message (struct transport *t)
{
  struct udp_transport *u = (struct udp_transport *)t;
  u_int8_t buf[UDP_SIZE];
  struct sockaddr_in from;
  int len = sizeof from;
  ssize_t n;
  struct message *msg;

  log_print("rekey_udp_handle_message: GOT A REKEY MESSAGE!!!");

  n = recvfrom (u->s, buf, UDP_SIZE, 0, (struct sockaddr *)&from,(socklen_t *)&len);
  if (n == -1)
    {
      log_error ("recvfrom (%d, %p, %d, %d, %p, %p)", u->s, buf, UDP_SIZE, 0,
		 &from, &len);
      return;
    }

  msg = message_alloc (t, buf, n);
  if (!msg)
    {
  	  log_print("rekey_udp_handle_message: No msg allocated");
      return;
	}
  rekey_message_recv (msg);
  transport_release (t);
}

/* Physically send the message MSG over its associated transport.  */
static int
rekey_udp_send_message (struct message *msg)
{
  struct udp_transport *u = (struct udp_transport *)msg->transport;
  ssize_t n;
  struct msghdr m;

  /*
   * Sending on connected sockets requires that no destination address is
   * given, or else EISCONN will occur.
   */
  m.msg_name = (caddr_t)&u->dst;
  m.msg_namelen = sizeof u->dst;
  m.msg_iov = msg->iov;
  m.msg_iovlen = msg->iovlen;
  m.msg_control = 0;
  m.msg_controllen = 0;
  m.msg_flags = 0;
  n = sendmsg (u->s, &m, 0);
  if (n == -1)
    {
      log_error ("sendmsg (%d, %p, %d)", u->s, &m, 0);
      return -1;
    }
  return 0;
}

enum {
    ReplayWindowSize = 32
};

int ChkReplayWindow(u_int32_t seq);

/*
 * Validate the sequence number.
 * HACK! THe following does not yet match the draft
 *
 * Cribbed from RFC 2401 Appendix C
 *
 * Returns 0 if packet disallowed, 1 if packet permitted 
 */
static int gdoi_seq_valid (struct gdoi_kek *stored_kek,  
						   u_int32_t received_seq)
{
  u_int32_t diff;

  if (received_seq == 0) return 0;                  /* first == 0 or wrapped */
  if (received_seq > stored_kek->current_seq_num) { 
  											   /* new larger sequence number */
      diff = received_seq - stored_kek->current_seq_num;
      if (diff < ReplayWindowSize) {        /* In window */
          stored_kek->replay_bitmap <<= diff;
          stored_kek->replay_bitmap |= 1;   /* set bit for this packet */
      } else stored_kek->replay_bitmap = 1; /* This packet has a "way larger" */
      stored_kek->current_seq_num = received_seq;
      return 1;                             /* larger is good */
  }
  diff = stored_kek->current_seq_num - received_seq;
  if (diff >= ReplayWindowSize) return 0;   /* too old or wrapped */
  if (stored_kek->replay_bitmap & ((u_int32_t)1 << diff)) return 0; 
                                                      /* already seen */
  stored_kek->replay_bitmap |= ((u_int32_t)1 << diff);  /* mark as seen */
  return 1;                                          /* out of order but good */
}

/*
 * Handle a rekey message. Note that it has already been decrypted.
 */
static int responder_recv_SEQ_SA_KD_SIG (struct message *msg)
{
  struct exchange *exchange = msg->exchange;
  struct payload *sigp, *p;
  struct gdoi_kek *stored_kek;
  u_int32_t seq;
  u_int8_t *begin, *end;
  struct hash *hash;
  u_int8_t *computed_hash, *decrypted_hash;
  int siglen, found_delete = 0;

  /*
   * Find the current KEK policy first.
   */
  stored_kek = gdoi_get_kek_by_cookies (exchange->cookies);
  if (!stored_kek)
 	{
   	  log_print ("responder_recv_SEQ_SA_KD_SIG: "
         	 	 "KEK policy missing from exchange");
  	  goto cleanup;
	}
  /*
   * Set the exchange name for reporting convienience and to match the
   * SAs up with other policy by name.
   */
  if (!exchange->name)
	{
	  exchange->name = strdup(stored_kek->exchange_name);
	}

  /* Handle SIG payload */
  sigp = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_SIG]);
  if (sigp)
    {
	  sigp->flags |= PL_MARK;
  	  /*
   	   * Compute the hash
   	   */
  	  hash = hash_get(xlate_gdoi_hash(stored_kek->sig_hash_alg));
  	  computed_hash = malloc (hash->hashsize);
	  if (!computed_hash)
	  	{
		  log_error ("responder_recv_SEQ_SA_KD_SIG: "
		  			 "malloc (%d) failed", hash->hashsize);
		}

  	  /* Start with the characters in 'rekey' */
  	  hash->Init (hash->ctx);
  	  LOG_DBG_BUF ((LOG_MISC, 90, "responder_recv_SEQ_SA_KD_SIG: 'rekey'", 
	  				(u_int8_t *)REKEY_HEADER_STRING, strlen(REKEY_HEADER_STRING)));
  	  hash->Update (hash->ctx, (u_int8_t *)REKEY_HEADER_STRING, 
	  			   strlen(REKEY_HEADER_STRING));
	  begin = msg->iov[0].iov_base;
	  end = sigp->p;
      LOG_DBG_BUF ((LOG_MISC, 90, 
	  				"responder_recv_SEQ_SA_KD_SIG: packet before SIG payload", 
	  				begin, (end-begin)));
	  hash->Update (hash->ctx, begin, (end-begin));
	  hash->Final (computed_hash, hash->ctx);
	  LOG_DBG_BUF ((LOG_NEGOTIATION, 80,
	  		"responder_recv_SEQ_SA_KD_SIG: computed hash",
	  		computed_hash, hash->hashsize));
	  /*
	   * Validate the signature
  	   * First check that the sig is of the correct size.
	   */
  	  siglen = GET_ISAKMP_GEN_LENGTH (sigp->p) - ISAKMP_SIG_SZ;
  	  if (siglen != RSA_size (stored_kek->rsa_keypair))
    	{
      	  log_print ("responder_recv_SEQ_SA_KD_SIG: "
					 "SIG payload length does not match public key");
      	  return -1;
    	}
  	  decrypted_hash = malloc (siglen);
  	  if (!decrypted_hash)
    	{
      	  log_error ("responder_recv_SEQ_SA_KD_SIG: "
		  			 "malloc (%d) failed", siglen);
      	  return -1;
    	}

	  siglen = RSA_public_decrypt (siglen, sigp->p + ISAKMP_SIG_DATA_OFF,
	  		   decrypted_hash, stored_kek->rsa_keypair, RSA_PKCS1_PADDING);
  	  if (siglen == -1)
    	{
		  ERR_load_crypto_strings();
      	  log_print ("responder_recv_SEQ_SA_KD_SIG: "
		  			 "RSA_public_decrypt () failed: %s",
					 ERR_error_string(ERR_get_error(),NULL));
		  free(decrypted_hash);
      	  return -1;
    	}
	  LOG_DBG_BUF ((LOG_NEGOTIATION, 80,
	  		"responder_recv_SEQ_SA_KD_SIG: decrypted hash",
	  		decrypted_hash, hash->hashsize));

	  if (memcmp(computed_hash, decrypted_hash, hash->hashsize))
	  	{
		  log_print("responder_recv_SEQ_SA_KD_SIG: "
		  			"Computed hash does not match decrypted hash!");
	  	  free(decrypted_hash);
		  return -1;
		}
	  free(decrypted_hash);
	}
  else
  {
	log_print("responder_recv_SEQ_SA_KD_SIG: Missing SIG payload!");
	goto cleanup;
  }

  /* Handle SEQ paylaod */
  p = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_SEQ]);
  if (p)
	{
  	  p->flags |= PL_MARK;
      seq = GET_GDOI_SEQ_SEQ_NUM(p->p);
      log_print ("GOT SEQ # of: %d (PUSH)", seq);
	  if (gdoi_seq_valid(stored_kek, seq))
	    {
	  	  stored_kek->current_seq_num = seq;
		}
	  else
	    {
		  log_print("responder_recv_SEQ_SA_KD_SIG: "
		  			"Sequence number out of range: previous %d, received %d",
					stored_kek->current_seq_num, seq);
		  goto cleanup;
		}
	}
  else
  {
	log_print("responder_recv_SEQ_SA_KD_SIG: Missing SEQ payload!");
	goto cleanup;
  }

  /*
   * There must be either an SA/KD pair, or DELETEs in the message, or both
   * (in which case the DELETEs are handled first).
   */
  p = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_DELETE]);
  if (p)
  	{
	  found_delete=1;
	  /*
	   * Loop through the DELETE payloads and handle them.
	   */
	   for (p = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_DELETE]); p;
	   		p = TAILQ_NEXT (p, link))
		  {
		    gdoi_process_delete_payload (msg, p);
		  }
	}

  p = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_SA]);
  if (p)
    {
  	  /* Handle SA payload */
  	  if (gdoi_process_SA_payload (msg))
		{
	  	  goto cleanup;
		}

  	  /* Handle KD payload */
  	  if (gdoi_process_KD_payload (msg))
		{
	  	  goto cleanup;
		}
	}
  else
	{
	  if (!found_delete)
		{
	  	  log_print("responder_recv_SEQ_SA_KD_SIG: Rekey message contains "
	  				"neither SA payload or DELETE paylaod. Aborting");
  	  	  goto cleanup;
		}
  	}

  return 0;

cleanup:
  /*
   * Return a non-error return, otherwise the message will get torn down, 
   * which tears down the transport, and then we don't receive any more rekey
   * messages. One bad message doesn't mean the rest will be bad (and could
   * even have been sent or replayed by an attacker.
   */
  log_print("responder_recv_SEQ_SA_KD_SIG: "
  			"Aborting processing of Rekey message");
  return 0;
}

/*
 * Find the given SA on any rekey exchange SA lists and remove it.
 */
void
gdoi_rekey_free_sa (struct sa *sa_to_remove)
{

  struct gdoi_kek *node;
  struct sa *sa;

  for (node = TAILQ_FIRST (&gdoi_kek_queue); node;
	   node = TAILQ_NEXT (node, link))
    {
		if (!node->send_exchange)
		  {
			continue;
		  }
		for (sa = TAILQ_FIRST (&node->send_exchange->sa_list);
			 sa; sa = TAILQ_NEXT (sa, next))
			  {
				if (sa == sa_to_remove)
				  {
					LOG_DBG ((LOG_SA, 60, "gdoi_rekey_free_sa: "
							 "freeing SA %p from exchange %p", 
							 sa, node->send_exchange));
					TAILQ_REMOVE (&node->send_exchange->sa_list, sa, next);
					/* 
					 * We're not deleting sa here, so it's pointer to the 
					 * next SA should be correct.
					 */
				  }
			  }	
	}
}
