/* $Id: gdoi_doi.c,v 1.13.2.3 2011/12/12 20:43:47 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/gdoi_doi.c,v $ */

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


#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#include "sysdep.h"
#include "conf.h"
#include "doi.h"
#include "crypto.h"
#include "hash.h"
#include "ike_aggressive.h"
#include "gdoi_fld.h"
#include "gdoi_num.h"
#include "ipsec_num.h"
#include "exchange.h"
#include "ike_main_mode.h"
#include "ike_auth.h"
#include "gdoi_phase2.h"
#include "gdoi.h"
#include "log.h"
#include "message.h"
#include "sa.h"
#include "util.h"
#include "transport.h"
#include "udp.h"
#include "ipsec.h"
#ifdef GDOI_APP_SUPPORT
#include "gdoi_app_client.h"
#include "gdoi_app_num.h"
#endif
#ifdef IEC90_5_SUPPORT
#include "gdoi_iec90_5_protos.h"
#endif

static int gdoi_debug_attribute (u_int16_t, u_int8_t *, u_int16_t, void *);
static void gdoi_delete_spi (struct sa *, struct proto *, int);
static u_int16_t *gdoi_exchange_script (u_int8_t);
static void gdoi_finalize_exchange (struct message *);
static void gdoi_free_exchange_data (void *);
static void gdoi_free_proto_data (void *);
static void gdoi_free_sa_data (void *);
static struct keystate *gdoi_get_keystate (struct message *);
static u_int8_t *gdoi_get_spi (size_t *, u_int8_t, struct message *);
int gdoi_handle_leftover_payload (struct message *, u_int8_t, struct payload *);
static int gdoi_informational_post_hook (struct message *);
static int gdoi_informational_pre_hook (struct message *);
void gdoi_proto_init (struct proto *, char *);
static int gdoi_initiator (struct message *);
static int gdoi_responder (struct message *);
static void gdoi_setup_situation (u_int8_t *);
static size_t gdoi_situation_size (void);
static u_int8_t gdoi_spi_size (u_int8_t);
static int gdoi_validate_attribute (u_int16_t, u_int8_t *, u_int16_t,
				      void *);
static int gdoi_validate_exchange (u_int8_t);
static int gdoi_validate_id_information (u_int8_t, u_int8_t *, u_int8_t *,
					   size_t, struct exchange *);
static int gdoi_validate_key_information (u_int8_t *, size_t);
static int gdoi_validate_notification (u_int16_t);
static int gdoi_validate_proto (u_int8_t);
static int gdoi_is_attribute_incompatible (u_int16_t, u_int8_t *, u_int16_t, 
                                           void *);
static int gdoi_validate_situation (u_int8_t *, size_t *);
static int gdoi_validate_transform_id (u_int8_t, u_int8_t);
static void gdoi_postprocess_sa (struct sa *);

static struct doi gdoi_doi = {
  { 0 }, GROUP_DOI_GDOI,
  sizeof (struct gdoi_exch), 
  sizeof (struct ipsec_sa),
  sizeof (struct ipsec_proto),
#ifdef USE_DEBUG
  gdoi_debug_attribute,
#endif
  gdoi_delete_spi,
  gdoi_exchange_script,
  gdoi_finalize_exchange,
  gdoi_free_exchange_data,
  gdoi_free_proto_data,
  gdoi_free_sa_data,
  gdoi_get_keystate,
  gdoi_get_spi,
  gdoi_handle_leftover_payload,
  gdoi_informational_post_hook,
  gdoi_informational_pre_hook,
  gdoi_is_attribute_incompatible,
  gdoi_proto_init,
  gdoi_setup_situation,
  gdoi_situation_size,
  gdoi_spi_size,
  gdoi_validate_attribute,
  gdoi_validate_exchange,
  gdoi_validate_id_information,
  gdoi_validate_key_information,
  gdoi_validate_notification,
  gdoi_validate_proto,
  gdoi_validate_situation,
  gdoi_validate_transform_id,
  gdoi_initiator,
  gdoi_responder,
  ipsec_decode_ids,
  gdoi_postprocess_sa
};

/*
 * Only mandatory payloads are specified.
 */
u_int16_t script_gdoi_registration[] = {
  ISAKMP_PAYLOAD_HASH,		/* Group member -> GCKS */
  ISAKMP_PAYLOAD_NONCE,
  ISAKMP_PAYLOAD_ID,
  EXCHANGE_SCRIPT_SWITCH,
  ISAKMP_PAYLOAD_HASH,		/* GCCK -> Group member */
  ISAKMP_PAYLOAD_NONCE,
  ISAKMP_PAYLOAD_SA,
  EXCHANGE_SCRIPT_SWITCH,
  ISAKMP_PAYLOAD_HASH,		/* Group member -> GCKS */
  EXCHANGE_SCRIPT_SWITCH,
  ISAKMP_PAYLOAD_HASH,		/* GCCK -> Group member */
  ISAKMP_PAYLOAD_KD,
  EXCHANGE_SCRIPT_END
};

u_int16_t script_gdoi_rekey[] = {
  ISAKMP_PAYLOAD_SEQ,		/* GCKS -> Group member */
  ISAKMP_PAYLOAD_SIG,
  EXCHANGE_SCRIPT_END
};


struct transport *gdoi_set_spi_transport;

/* Requires doi_init to already have been called.  */
void
gdoi_init ()
{
  doi_register (&gdoi_doi);

  gdoi_rekey_init();

  gdoi_phase2_init();

  /*
   * Create a transport structure to use termporily to install SPIs into the
   * kernel. We need this because the SA src/dst don't come already associated
   * with the SA transport, as in IKE.
   */
  gdoi_set_spi_transport = transport_create ("rekey_udp", "GDOI-SET-SPI");
  if (!gdoi_set_spi_transport)
    {
	  log_error ("gdoi_init: Error: couldn't create GDOI-SET-SPI transport");
	  return;
	}

#ifdef GDOI_APP_SUPPORT
  /*
   * Start the application listening pipe, if it is configured.
   */

  if (conf_get_str ("General", "GDOI-application-client-support"))
    {
	  gdoi_app_client_init();  
    }
#endif
}

/*
 * Check that a received message on a GDOI exchange is valid.
 */
int
gdoi_validate_gdoi_exchange_special (struct message *msg)
{
  struct exchange *exchange = msg->exchange;
  struct doi *doi = exchange->doi;
  struct gdoi_kek *stored_kek;

  if (doi->id != GROUP_DOI_GDOI)
	{
	  log_print ("gdoi_validate_gdoi_exchange_special: "
			     "Not a GDOI exchange. Aborting.");
	  return -1;
	}

  if (exchange->type == GDOI_EXCH_PUSH_MODE)
	{
  	  stored_kek = gdoi_get_kek_by_cookies(exchange->cookies);
  	  if (!stored_kek)
  		{
	  	  log_print ("gdoi_validate_gdoi_exchange_special: "
				 	 "No cookies found for GDOI rekey. Aborting.");
	  	  return -1;
		}
	  /*
	   * Verify that the receiver isn't a key server receiving a rekey
	   * message.
	   */
	  if (stored_kek->send_exchange == exchange)
	    {
	  	  log_print ("gdoi_validate_gdoi_exchange_special: "
				 	 "Key server should not be receiving messages on "
					 "the rekey SA! Aborting.");
	  	  return -1;
		}
	}

  return 0;
}

#ifdef USE_DEBUG
int
gdoi_debug_attribute (u_int16_t type, u_int8_t *value, u_int16_t len,
			void *vmsg)
{
  /* XXX Not implemented yet.  */
  return 0;
}
#endif

/*
 * Delete the IPSec SA represented by the INCOMING direction in protocol PROTO
 * of the IKE security association SA.
 */
static void
gdoi_delete_spi (struct sa *sa, struct proto *proto, int incoming)
{
  struct udp_transport *u;
#ifdef USE_DEBUG
  struct ipsec_sa *isa = (struct ipsec_sa *)sa->data;
#endif

  if (sa->phase == 1)
    return;
 
  LOG_DBG ((LOG_EXCHANGE, 50, 
 	  "gdoi_delete_spi: Asked to delete SPI for src %x %x dst %x %x",
	  ntohl (isa->src_net), ntohl (isa->src_mask),
	  ntohl (isa->dst_net), ntohl (isa->dst_mask)));
  
  sa->transport = gdoi_set_spi_transport;
  u = (struct udp_transport *) sa->transport;
  u->src.sin_family = AF_INET;
  u->src.sin_addr.s_addr = isa->src_net;
  u->dst.sin_family = AF_INET;
  u->dst.sin_addr.s_addr = isa->dst_net;

  sysdep_ipsec_delete_spi (sa, proto, incoming);

  sa->transport = NULL;

  return;
}

/* Return exchange script based on TYPE.  */
static u_int16_t *
gdoi_exchange_script (u_int8_t type)
{
  switch (type)
    {
    case GDOI_EXCH_PULL_MODE:
      return script_gdoi_registration;
    case GDOI_EXCH_PUSH_MODE:
      return script_gdoi_rekey;
    }
  return 0;
}

void
gdoi_ipsec_deliver_keys (struct message *msg, struct sa *sa)
{
  struct proto *proto;
  struct ipsec_sa *isa = (struct ipsec_sa *)sa->data;
  struct udp_transport *u;

  struct sa *isakmp_sa;
  
  proto =  TAILQ_FIRST (&sa->protos);
  if (!proto)
  	{
      log_error ("gdoi_ipsec_deliver_keys: IPsec SA proto data missing");
       return;
  	}

  /*
   * Add a transport to the SA for the purposes of setting the SPI.
   */
  sa->transport = gdoi_set_spi_transport;
  u = (struct udp_transport *) sa->transport;
  /*
   * Assume IPv4
   * BEW: Should be passing the mask to the PF_KEY code so that it can
   *      put it in sadb_address_prefixlen! 
   */
  u->src.sin_addr.s_addr = isa->src_net;
  u->src.sin_family = AF_INET;
  u->dst.sin_addr.s_addr = isa->dst_net;
  u->dst.sin_family = AF_INET;
  if (sysdep_ipsec_set_spi (sa, proto, 0))
   	{
  	  sa->transport = NULL;
   	  log_error ("gdoi_ipsec_deliver_keys: "
		     "sysdep_ipsec_set_spi failed (out)");
      return;
	}

  /*
   * sysdep_ipsec_enable_sa() uses the id's in the isakmp_sa, which isn't
   * correct for GDOI -- those id's (key server, client) have nothing to do 
   * with the group SAs. We need to carefully craft a useful isakmp_sa.
   */
  isakmp_sa = malloc(sizeof(struct sa));
  if (!isakmp_sa) {
  	sa->transport = NULL;
	log_error ("gdoi_ipsec_deliver_keys: malloc (%d) failed", 
			   sizeof(struct sa)); 
	return;
  }

  /*
   * Setup an isamp_sa with NULL id_i and id_r fields.
   */
   isakmp_sa->id_i = NULL;
   isakmp_sa->id_r = NULL;
  if (sysdep_ipsec_enable_sa (sa, isakmp_sa))
	{
   	  log_error ("gdoi_ipsec_deliver_keys: "
		     "sysdep_ipsec_enable_sa failed (out)");
   	  goto clean_up;
	}
	  
  sa->transport = NULL;
  LOG_DBG ((LOG_EXCHANGE, 50,
 			  "gdoi_ipsec_deliver_keys: src %x %x dst %x %x",
			  ntohl (isa->src_net), ntohl (isa->src_mask),
			  ntohl (isa->dst_net), ntohl (isa->dst_mask)));

clean_up:

  sa->transport = NULL;
  if (isakmp_sa->id_i)
	free(isakmp_sa->id_i);
  if (isakmp_sa->id_r)
	free(isakmp_sa->id_r);
  free(isakmp_sa);

  return;
}

static void
gdoi_install_sas (struct message *msg)
{
  struct exchange *exchange = msg->exchange; 
  struct gdoi_exch *ie = exchange->data;
  struct sa *sa = 0, *old_sa;

  /*
   * If this is the client side (initiator of the exchange), tell 
   * the application(s) about the SPIs and key material.
   */
  for (sa = TAILQ_FIRST (&exchange->sa_list); sa;
       sa = TAILQ_NEXT (sa, next))
  	{ 
      if (!sa->data)
    	{
      	  log_print ("gdoi_install_sas: "
       	    		 "SA DOI specific data missing");
      	  return;
		}
	  switch (ie->teks_type)
		{
      	case GDOI_TEK_PROT_PROTO_IPSEC_ESP:
      	case GDOI_TEK_PROT_PROTO_IPSEC_AH:
	      gdoi_ipsec_deliver_keys(msg, sa);
	      break;
#ifdef IEC90_5_SUPPORT
      	case GDOI_TEK_PROT_PROTO_IEC90_5:
	      gdoi_app_deliver_app_data(GDOI_PROTO_IEC90_5, sa);
	      break;
#endif
#ifdef SRTP_SUPPORT
      	case GDOI_TEK_PROT_PROTO_SRTP:
	      gdoi_app_deliver_app_data(GDOI_PROTO_SRTP, sa);
	      break;
#endif
		default:
  	      log_print ("gdoi_install_sas: "
       	  		     "Unsupported TEK type: %d", ie->teks_type);
  	      return;
		}

        /* Mark elder SAs with the same flow info as replaced.  */
        while ((old_sa = sa_find (ipsec_sa_check_flow, sa)) != 0)
        {
	  	  sa_mark_replaced (old_sa);
		}
    }
}

/*
 * Convert the unsigned LEN-sized number at BUF of network byteorder to a
 * 32-bit unsigned integer of host byteorder pointed to by VAL.
 */
static int
extract_val (u_int8_t *buf, size_t len, u_int32_t *val)
{
  switch (len)
    {
    case 1:
      *val = *buf;
      break;
    case 2:
      *val = decode_16 (buf);
      break;
    case 4:
      *val = decode_32 (buf);
      break;
    default:
      return -1;
    }
  return 0;
}

/*
 * return a group ID for displaying in a debug message.
 *
 * WARNING: The string comes from a static location, so mustn't be
 *          stored anywhere!
 */
u_int8_t *
gdoi_display_group_id (char *id)
{
  static u_int8_t id_str[20];
  int type = GET_ISAKMP_ID_TYPE((u_int8_t *)id); 
  u_int32_t value;

  strncpy((char *)id_str, "UNKNOWN", 8);
  switch (type)
    {
    case IPSEC_ID_KEY_ID:
      /* Assume Group ID is a 32-bit number */
	  extract_val((u_int8_t *)id + ISAKMP_ID_DATA_OFF, 4, &value);
      sprintf((char *)id_str, "%d", value);
      break;
    default:
      log_print ("gdoi_display_group_id: unsupported identity type %d", type);
      break;
    }
  return id_str;
}

/*
 * Do GDOI specific finalizations task for the exchange where MSG was
 * the final message.
 */
static void
gdoi_finalize_exchange (struct message *msg)
{
  struct sa *isakmp_sa, *sa;
  struct ipsec_sa *isa;
  struct exchange *exchange = msg->exchange;
  struct gdoi_exch *ie = exchange->data;
  struct gdoi_kek *kek;

  switch (exchange->phase)
    {
    case 1:
      switch (exchange->type)
		{
		case ISAKMP_EXCH_ID_PROT:
		case ISAKMP_EXCH_AGGRESSIVE:
		  isakmp_sa = msg->isakmp_sa;
		  isa = isakmp_sa->data;
		  isa->hash = ie->hash->type;
		  isa->prf_type = ie->prf_type;
		  isa->skeyid_len = ie->skeyid_len;
		  isa->skeyid_d = ie->skeyid_d;
		  isa->skeyid_a = ie->skeyid_a;
		  /* Prevents early free of SKEYID_*.  */
		  ie->skeyid_a = ie->skeyid_d = 0;
	
		  /* If a lifetime was negotiated setup the expiration timers.  */
		  if (isakmp_sa->seconds)
		    sa_setup_expirations (isakmp_sa);
		  LOG_DBG ((LOG_EXCHANGE, 50,
				 "gdoi_finalize_exchange: DONE WITH PHASE 1!!!\n"));
		  break;
		case GDOI_EXCH_PUSH_MODE:
		  if (exchange->initiator)
		    {
			  /*
			   * Setup SA expirations.
			   */
  			  for (sa = TAILQ_FIRST (&exchange->sa_list); sa;
       			   sa = TAILQ_NEXT (sa, next))
  				{
				  if (sa->seconds && !sa->death)
					{
					   sa_setup_expirations (sa);
					}
				}
		  	 LOG_DBG ((LOG_EXCHANGE, 50,
				"gdoi_finalize_exchange: "
				"DONE WITH REKEY (SEND): Group %s!!!\n",
				gdoi_display_group_id((char *)ie->id_gdoi)));
			}
		  else
		  	{
			  /*
			   * Let the lower layer code setup the expirations (e.g., pf-key
			   * handing code for IPSec.)
			   */
			  gdoi_install_sas (msg);
		  	  LOG_DBG ((LOG_EXCHANGE, 50,
				 "gdoi_finalize_exchange: DONE WITH REKEY (RECEIVE)!!!\n"));
			}
		  break;
		default:
		  LOG_DBG ((LOG_EXCHANGE, 50,
				 "gdoi_finalize_exchange: Invalid exchange for phase 1 (%d)",
				 exchange->type));
		}
      break;

    case 2:
      switch (exchange->type)
		{
		case GDOI_EXCH_PULL_MODE:
		  if (exchange->initiator)
		  	{
			  gdoi_install_sas (msg);
			}
		  else
		    {
			  /*
			   * Setup SA expirations.
			   *
			   * If the SA list for the exchange is empty, then the SAs
			   * are on the rekey list.
			   */
			  sa = TAILQ_FIRST (&exchange->sa_list);
			  if (!sa)
			  	{
				  kek = gdoi_get_kek(ie->id_gdoi, ie->id_gdoi_sz, 0);
				  if (!kek)
				  	{
		  	  		  LOG_DBG ((LOG_EXCHANGE, 50,
				 	  			 "gdoi_finalize_exchange: "
								 "No KEK found! \n"));
					  return;
					}
				  sa = TAILQ_FIRST (&kek->send_exchange->sa_list);
				  if (!sa)
				  	{
		  	  		  LOG_DBG ((LOG_EXCHANGE, 50,
				 	  			 "gdoi_finalize_exchange: "
								 "No SAs found! \n"));
					  return;
					}
				}
			  while (sa)
  				{ 
				  if (sa->seconds && !sa->death)
					{
					   sa_setup_expirations (sa);
					}
				  sa = TAILQ_NEXT (sa, next);
				}
			}
		  LOG_DBG ((LOG_EXCHANGE, 50,
				 "gdoi_finalize_exchange: DONE WITH PHASE 2!!!\n"));
		  break;
		default:
		  LOG_DBG ((LOG_EXCHANGE, 50,
				 "gdoi_finalize_exchange: Invalid exchange for phase 2 (%d)",
				 exchange->type));
		}
    }
}

/* Free the DOI-specific exchange data pointed to by VIE.  */
static void
gdoi_free_exchange_data (void *vie)
{
  return;
}

/* Free the DOI-specific protocol data of an SA pointed to by VIPROTO.  */
static void
gdoi_free_proto_data (void *viproto)
{
  return;
}

/* Free the DOI-specific SA data pointed to by VISA.  */
static void
gdoi_free_sa_data (void *visa)
{
  struct ipsec_sa *isa = visa;

  if (isa->skeyid_a)
    free (isa->skeyid_a);
  if (isa->skeyid_d)
    free (isa->skeyid_d);
}

static struct keystate *
gdoi_get_keystate (struct message *msg)
{
  struct keystate *ks;
  struct hash *hash;

  /* If we have already have an IV, use it.  */
  if (msg->exchange && msg->exchange->keystate)
    {
      ks = malloc (sizeof *ks);
      if (!ks)
	{
	  log_error ("gdoi_get_keystate: malloc (%d) failed", sizeof *ks);
	  return 0;
	}
      memcpy (ks, msg->exchange->keystate, sizeof *ks);
      return ks;
    }

  /*
   * For phase 2 when no SA yet is setup we need to hash the IV used by
   * the ISAKMP SA concatenated with the message ID, and use that as an
   * IV for further cryptographic operations.
   */
  ks = crypto_clone_keystate (msg->isakmp_sa->keystate);
  if (!ks)
    return 0;

  hash = hash_get (((struct ipsec_sa *)msg->isakmp_sa->data)->hash);
  hash->Init (hash->ctx);
  LOG_DBG_BUF ((LOG_CRYPTO, 80, "gdoi_get_keystate: final phase 1 IV",
		 ks->riv, ks->xf->blocksize));
  hash->Update (hash->ctx, ks->riv, ks->xf->blocksize);
  LOG_DBG_BUF ((LOG_CRYPTO, 80, "gdoi_get_keystate: message ID",
		 ((u_int8_t *)msg->iov[0].iov_base)
		 + ISAKMP_HDR_MESSAGE_ID_OFF,
		 ISAKMP_HDR_MESSAGE_ID_LEN));
  hash->Update (hash->ctx,
		((u_int8_t *)msg->iov[0].iov_base) + ISAKMP_HDR_MESSAGE_ID_OFF,
		ISAKMP_HDR_MESSAGE_ID_LEN);
  hash->Final ((u_int8_t *)hash->digest, hash->ctx);
  crypto_init_iv (ks, (u_int8_t *)hash->digest, ks->xf->blocksize);
  LOG_DBG_BUF ((LOG_CRYPTO, 80, "gdoi_get_keystate: phase 2 IV",
		 (u_int8_t *)hash->digest, ks->xf->blocksize));
  return ks;
}

/*
 * Get a SPI for PROTO and the transport MSG passed over.  Store the
 * size where SZ points.  NB!  A zero return is OK if *SZ is zero.
 */
static u_int8_t *
gdoi_get_spi (size_t *sz, u_int8_t proto, struct message *msg)
{
  if (msg->exchange->phase == 1)
    {
      *sz = 0;
      return 0;
    }
  else
    {
    /*
     * Return no SPI for now -- SPIs must be manually specified in the 
     * config file for now.
     */
    *sz = 0;
    return 0;
    }
}

/*
 * We have gotten a payload PAYLOAD of type TYPE, which did not get handled
 * by the logic of the exchange MSG takes part in.  Now is the time to deal
 * with such a payload if we know how to, if we don't, return -1, otherwise
 * 0.
 */
int
gdoi_handle_leftover_payload (struct message *msg, u_int8_t type,
			       struct payload *payload)
{
  return -1;
}

/* Add a HASH payload to MSG, if we have an ISAKMP SA we're protected by.  */
static int
gdoi_informational_pre_hook (struct message *msg)
{
#ifdef NOTYET
  struct sa *isakmp_sa = msg->isakmp_sa;
  struct gdoi_sa *isa;
  struct hash *hash;

  if (!isakmp_sa)
    return 0;
  isa = isakmp_sa->data;
  hash = hash_get (isa->hash);
  return ipsec_add_hash_payload (msg, hash->hashsize) == 0;
#else
  return -1;
#endif
}

/*
 * Fill in the HASH payload in MSG, if we have an ISAKMP SA we're protected by.
 */
static int
gdoi_informational_post_hook (struct message *msg)
{
#ifdef NOTYET
  if (!msg->isakmp_sa)
    return 0;
  return ipsec_fill_in_hash (msg);
#else
  return -1;
#endif
}

enum hashes xlate_gdoi_hash (u_int16_t hash)
{
  switch (hash)
    {
    case GDOI_KEK_HASH_ALG_MD5:
      return HASH_MD5;
    case GDOI_KEK_HASH_ALG_SHA:
      return HASH_SHA1;
    case GDOI_KEK_HASH_ALG_SHA256:
	  return HASH_SHA256;
    }
  return -1;
}

/* XXX Copied from ipsec.c */
static enum transform from_ike_crypto (u_int16_t crypto)
{
  /* Coincidentally this is the null operation :-)  */
  return crypto;
}


/*
 * Find out whether the attribute of type TYPE with a LEN length value
 * pointed to by VALUE is incompatible with what we can handle.
 * VMSG is a pointer to the current message.
 */
int
gdoi_is_attribute_incompatible (u_int16_t type, u_int8_t *value,
				 u_int16_t len, void *vmsg)
{
  struct message *msg = vmsg;

  if (msg->exchange->phase == 1)
    {
      switch (type)
	{
	case IKE_ATTR_ENCRYPTION_ALGORITHM:
	  return !crypto_get (from_ike_crypto (decode_16 (value)));
	case IKE_ATTR_HASH_ALGORITHM:
	  return !hash_get (xlate_gdoi_hash (decode_16 (value)));
	case IKE_ATTR_AUTHENTICATION_METHOD:
	  return !ike_auth_get (decode_16 (value));
	case IKE_ATTR_GROUP_DESCRIPTION:
	  return decode_16 (value) < IKE_GROUP_DESC_MODP_768
	    || decode_16 (value) > IKE_GROUP_DESC_MODP_1536;
	case IKE_ATTR_GROUP_TYPE:
	  return 1;
	case IKE_ATTR_GROUP_PRIME:
	  return 1;
	case IKE_ATTR_GROUP_GENERATOR_1:
	  return 1;
	case IKE_ATTR_GROUP_GENERATOR_2:
	  return 1;
	case IKE_ATTR_GROUP_CURVE_A:
	  return 1;
	case IKE_ATTR_GROUP_CURVE_B:
	  return 1;
	case IKE_ATTR_LIFE_TYPE:
	  return decode_16 (value) < IKE_DURATION_SECONDS
	    || decode_16 (value) > IKE_DURATION_KILOBYTES;
	case IKE_ATTR_LIFE_DURATION:
	  return 0;
	case IKE_ATTR_PRF:
	  return 1;
	case IKE_ATTR_KEY_LENGTH:
	  /*
	   * Our crypto routines only allows key-lengths which are multiples
	   * of an octet.
	   */
	  return decode_16 (value) % 8 != 0; 
	case IKE_ATTR_FIELD_SIZE:
	  return 1;
	case IKE_ATTR_GROUP_ORDER:
	  return 1;
	}
    }
  else
    {
    	/* Nothing to do. */
    }
  /* XXX Silence gcc.  */
  return 1;
}

/*
 * IPSec-specific PROTO initializations.  SECTION is only set if we are the
 * initiator thus only usable there.
 * XXX I want to fix this later.
 */
void
gdoi_proto_init (struct proto *proto, char *section)
{
  /* Nothing to do. */
}

static void
gdoi_setup_situation (u_int8_t *buf)
{
   SET_GDOI_SIT_SIT (buf + ISAKMP_SA_SIT_OFF, 0 /* As of GDOI draft 1 */);
}

static size_t
gdoi_situation_size (void)
{
  return GDOI_SIT_SIT_LEN;
}

static u_int8_t
gdoi_spi_size (u_int8_t proto)
{
  /* One way to specify ISAKMP SPIs is to say they're zero-sized.  */
  return 0;
}

static int
gdoi_validate_attribute (u_int16_t type, u_int8_t *value, u_int16_t len,
			   void *vmsg)
{
  struct message *msg = vmsg;

  if ((msg->exchange->phase == 1
       && (type < IKE_ATTR_ENCRYPTION_ALGORITHM
	   || type > IKE_ATTR_GROUP_ORDER))
      || (msg->exchange->phase == 2
	  && (type < IPSEC_ATTR_SA_LIFE_TYPE
	      || type > IPSEC_ATTR_COMPRESS_PRIVATE_ALGORITHM)))
    return -1;
  return 0;
}

static int
gdoi_validate_exchange (u_int8_t exch)
{
  /* If we get here the exchange is invalid.  */
  return exch != GDOI_EXCH_PULL_MODE && exch != GDOI_EXCH_PUSH_MODE;
}

static int
gdoi_validate_id_information (u_int8_t type, u_int8_t *extra, u_int8_t *buf,
				size_t sz, struct exchange *exchange)
{
  u_int8_t proto = GET_IPSEC_ID_PROTO (extra);
  u_int16_t port = GET_IPSEC_ID_PORT (extra);

  LOG_DBG ((LOG_MESSAGE, 0, 
	     "gdoi_validate_id_information: proto %d port %d type %d",
	     proto, port, type));
  if (type < IPSEC_ID_IPV4_ADDR || type > IPSEC_ID_IEC90_5)
    return -1;

  switch (type)
    {
    case IPSEC_ID_IPV4_ADDR:
      LOG_DBG_BUF ((LOG_MESSAGE, 40, "gdoi_validate_id_information: IPv4",
		     buf, 4));
      break;

    case IPSEC_ID_IPV4_ADDR_SUBNET:
      LOG_DBG_BUF ((LOG_MESSAGE, 40,
		     "gdoi_validate_id_information: IPv4 network/netmask",
		     buf, 8));
      break;

    case IPSEC_ID_KEY_ID:
      LOG_DBG ((LOG_MESSAGE, 40, "gdoi_validate_id_information: key id %s",
		     buf));
      break;

#ifdef IEC90_5_SUPPORT
    case IPSEC_ID_IEC90_5:
	  if (iec90_5_validate_id_information(buf)) {
		log_print ("gdoi_validate_id_information: IEC90-5 validation failed\n");
	    return -1;
	  }
	  break;
#endif

    default:
      break;
    }

  if (exchange->phase == 1
      && (proto != IPPROTO_UDP || port != UDP_DEFAULT_PORT)
      && (proto != 0 || port != 0))
    {
/* XXX SSH's ISAKMP tester fails this test (proto 17 - port 0).  */
#ifdef notyet
      return -1;
#else
      log_print ("gdoi_validate_id_information: "
		 "dubious ID information accepted");
#endif
    }

  /* XXX More checks?  */

  return 0;
}

static int
gdoi_validate_key_information (u_int8_t *buf, size_t sz)
{
  /* Nothing to do.  */
  return 0;
}

static int
gdoi_validate_notification (u_int16_t type)
{
    return type < IPSEC_NOTIFY_RESPONDER_LIFETIME
	|| type > IPSEC_NOTIFY_INITIAL_CONTACT ? -1 : 0;
}

static int
gdoi_validate_proto (u_int8_t proto)
{
  if (!constant_lookup(gdoi_tek_prot_cst, proto))
  	{
      log_print ("gdoi_validate_proto: unsupported TEK protocol %d", proto);
  	  return -1;
	}
  return 0;
}

static int
gdoi_validate_situation (u_int8_t *buf, size_t *sz)
{
  int sit = GET_GDOI_SIT_SIT (buf);

  /*
   * As of GDOI Draft 1, no situation bits are in use.
   */
  if (sit != 0) {
      *sz = 0;
      return -1;
  }

  *sz = 4;
  return 0;
}

static int
gdoi_validate_transform_id (u_int8_t proto, u_int8_t transform_id)
{
  switch (proto)
    {
      /*
       * As no unexpected protocols can occur, we just tie the default case
       * to the first case, in orer to silence a GCC warning.
       */
    default:
    case ISAKMP_PROTO_ISAKMP:
      return transform_id != IPSEC_TRANSFORM_KEY_IKE;
    case IPSEC_PROTO_IPSEC_AH:
      return
	transform_id < IPSEC_AH_MD5 
				|| transform_id > IPSEC_AH_SHA2_512 ? -1 : 0;
    case IPSEC_PROTO_IPSEC_ESP:
      return transform_id < IPSEC_ESP_DES_IV64
				|| transform_id > IPSEC_ESP_AES_NULL_AUTH_AES_GMAC  ? -1 : 0;
    case IPSEC_PROTO_IPCOMP:
      return transform_id < IPSEC_IPCOMP_OUI
	|| transform_id > IPSEC_IPCOMP_V42BIS ? -1 : 0;
    }
}

/*
 * If applicable, unlink the SA from the rekey exchange.
 */
static void
gdoi_postprocess_sa (struct sa *sa)
{
  struct gdoi_kek *stored_kek;

  /*
   * The SA might have already been deleted. This is likely on
   * the group member side where we have no postprocessing to do.
   */
  if (sa->refcnt == 0)
  	{
	  return;
	}

  /*
   * This is probably an error.
   */
  if ((int16_t)sa->refcnt < 0)
  	{
  	  LOG_DBG ((LOG_SA, 50, 
 	  		"gdoi_postprocess_sa: SA %p has invalid reference count %d",
			 sa, sa->refcnt));
	  return;
	}

  stored_kek = gdoi_get_kek_by_cookies(sa->cookies);
  if (!stored_kek)
  	{
	  return;
	}

  if (stored_kek->send_exchange)
  	{
  	  TAILQ_REMOVE(&stored_kek->send_exchange->sa_list, sa, next);
	}
  sa_release (sa);

  return;
}

static int
gdoi_initiator (struct message *msg)
{
  struct exchange *exchange = msg->exchange;
  int (**script) (struct message *msg) = 0;
  
  /* Check that the SA is coherent with the GDOI rules.  */
  if ((exchange->phase == 1 && exchange->type != ISAKMP_EXCH_ID_PROT
       && exchange->type != ISAKMP_EXCH_AGGRESSIVE
       && exchange->type != GDOI_EXCH_PUSH_MODE
       && exchange->type != ISAKMP_EXCH_INFO)
      || (exchange->phase == 2 && exchange->type != GDOI_EXCH_PULL_MODE
       && exchange->type != ISAKMP_EXCH_INFO))
    {
      log_print ("gdoi_initiator: unsupported exchange type %d in phase %d",
		 exchange->type, exchange->phase);
      return -1;
    }
    
  switch (exchange->type)
    {
    case ISAKMP_EXCH_ID_PROT:
      script = ike_main_mode_initiator;
      break;
#ifdef USE_AGGRESSIVE
    case ISAKMP_EXCH_AGGRESSIVE:
      script = ike_aggressive_initiator;
      break;
#endif
    case ISAKMP_EXCH_INFO:
      return message_send_info (msg);
    case GDOI_EXCH_PULL_MODE:
      script = gdoi_phase2_initiator;
      break;
    case GDOI_EXCH_PUSH_MODE:
      script = gdoi_rekey_initiator;
      break;
    default:
      log_print ("gdoi_initiator: unuspported exchange type %d",
		 exchange->type);
      return -1;
    }

  /* Run the script code for this step.  */
  if (script)
    return script[exchange->step] (msg);

  return 0;
}

static int
gdoi_responder (struct message *msg)
{
  struct exchange *exchange = msg->exchange;
  int (**script) (struct message *msg) = 0;

  /* Check that a new exchange is coherent with the GDOI rules.  */
  if (exchange->step == 0
      && ((exchange->phase == 1 && exchange->type != ISAKMP_EXCH_ID_PROT
	   && exchange->type != ISAKMP_EXCH_AGGRESSIVE
       	   && exchange->type != GDOI_EXCH_PUSH_MODE)
	  || (exchange->phase == 2 && exchange->type == ISAKMP_EXCH_ID_PROT)))
    {
      message_drop (msg, ISAKMP_NOTIFY_UNSUPPORTED_EXCHANGE_TYPE, 0, 1, 0);
      return -1;
    }
    
  LOG_DBG ((LOG_MISC, 30,
	     "gdoi_responder: phase %d exchange %d step %d", exchange->phase,
	     exchange->type, exchange->step));
  switch (exchange->type)
    {
    case ISAKMP_EXCH_ID_PROT:
      script = ike_main_mode_responder;
      break;

#ifdef USE_AGGRESSIVE
    case ISAKMP_EXCH_AGGRESSIVE:
      script = ike_aggressive_responder;
      break;
#endif

    case GDOI_EXCH_PULL_MODE:
      script = gdoi_phase2_responder;
      break;
    
    case GDOI_EXCH_PUSH_MODE:
      script = gdoi_rekey_responder;
      break;

    default:
      message_drop (msg, ISAKMP_NOTIFY_UNSUPPORTED_EXCHANGE_TYPE, 0, 1, 0);
      return -1;
    }

  /* Run the script code for this step.  */
  if (script)
    return script[exchange->step] (msg);

  return 0;
}

int
gdoi_validate_kd (struct message *msg, struct payload *p)
{
  return 0;
}

int
gdoi_validate_seq (struct message *msg, struct payload *p)
{
  return 0;
}

int
gdoi_validate_gap (struct message *msg, struct payload *p)
{
  return 0;
}
