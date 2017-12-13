/* $Id: gdoi_phase2.c,v 1.22.2.3 2011/12/12 20:43:47 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/gdoi_phase2.c,v $ */

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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "sysdep.h"

#include "attribute.h"
#include "conf.h"
#include "connection.h"
#include "dh.h"
#include "doi.h"
#include "exchange.h"
#include "hash.h"
#include "gdoi_phase2.h"
#include "gdoi.h"
#include "ipsec.h"
#include "log.h"
#include "math_group.h"
#include "message.h"
#include "prf.h"
#include "sa.h"
#include "transport.h"
#include "crypto.h"
#include "util.h"
#include "gdoi_fld.h"
#include "gdoi_num.h"
#include "x509.h"
#include "cert.h"
#include "libcrypto.h"
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#ifdef IEC90_5_SUPPORT
#include "gdoi_iec90_5_protos.h"
#include "gdoi_iec90_5.h"
#include "iec90_5_num.h"
#endif
#ifdef SRTP_SUPPORT
#include "gdoi_srtp_protos.h"
#include "gdoi_srtp.h"
#endif

#define DES_LENGTH 8
#define MAX_PUBKEY_SIZE 1024

enum i_hash_inc { NO_I_NONCE, INC_I_NONCE };
enum r_hash_inc { NO_R_NONCE, INC_R_NONCE };

#define SRC 1
#define DST 2

#define DEFAULT_REKEY_PERIOD 10
#define DEFAULT_KEK_REKEY_PERIOD 25

#define ATTR_SIZE (50 * ISAKMP_ATTR_VALUE_OFF)

u_int8_t empty_cookies[KEK_SPI_SIZE];

static int initiator_send_HASH_NONCE_ID (struct message *);
static int initiator_recv_HASH_NONCE_SA (struct message *);
static int initiator_send_HASH (struct message *);
static int initiator_recv_HASH_SEQ_KD (struct message *);
static int responder_recv_HASH_NONCE_ID (struct message *);
static int responder_send_HASH_NONCE_SA (struct message *);
static int responder_recv_HASH (struct message *);
static int responder_send_HASH_SEQ_KD (struct message *);

int (*gdoi_phase2_initiator[]) (struct message *) = {
  initiator_send_HASH_NONCE_ID,
  initiator_recv_HASH_NONCE_SA,
  initiator_send_HASH,
  initiator_recv_HASH_SEQ_KD
};

int (*gdoi_phase2_responder[]) (struct message *) = {
  responder_recv_HASH_NONCE_ID,
  responder_send_HASH_NONCE_SA,
  responder_recv_HASH,
  responder_send_HASH_SEQ_KD
};

struct extended_attrs {
  TAILQ_ENTRY (extended_attrs) link;
  size_t sz;
  int has_generic_header;
  int attr_type;
  void *attr_payload;
};
  
static TAILQ_HEAD (attr_payload_list, extended_attrs) attr_payloads;

#define MAX_PRINT_STRING_LEN 4096
static char bit_string[MAX_PRINT_STRING_LEN]; /* Cheap way of returning a string -- should be save in a single-threaded daemon */

/*
 * Initialization for this file.
 */
void gdoi_phase2_init(void)
{
  memset(empty_cookies, 0, KEK_SPI_SIZE);
}

uint8_t
nibble_to_hex_char(uint8_t nibble) {
  char buf[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
		  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
  return buf[nibble & 0xF];
}

char *
octet_string_hex_string(const void *s, int length) {
  const uint8_t *str = (const uint8_t *)s;
  int i;
  
  /* double length, since one octet takes two hex characters */
  length *= 2;

  /* truncate string if it would be too long */
  if (length > MAX_PRINT_STRING_LEN)
    length = MAX_PRINT_STRING_LEN-1;
  
  for (i=0; i < length; i+=2) {
    bit_string[i]   = nibble_to_hex_char(*str >> 4);
    bit_string[i+1] = nibble_to_hex_char(*str++ & 0xF);
  }
  bit_string[i] = 0; /* null terminate string */
  return bit_string;
}

/*
 * Out of a named section SECTION in the configuration file find out
 * the group identity information. Modelled after ipsec_get_id().
 */
static int
group_get_id (char *section, int *id, size_t *id_sz, u_int8_t **buf)
{
  char *type, *group;
  u_int32_t group_id;
  u_int8_t *local_buf;

  type = conf_get_str (section, "ID-type");
  if (!type)
    {
      log_print ("group_get_id: section %s has no \"ID-type\" tag", section);
      return -1;
    }

  *id = constant_value (ipsec_id_cst, type);
  switch (*id)
    {
    case IPSEC_ID_IPV4_ADDR:
      return -1;

    case IPSEC_ID_FQDN:
      return -1;

    case IPSEC_ID_USER_FQDN:
      return -1;

    case IPSEC_ID_IPV4_ADDR_SUBNET:
      return -1;

    case IPSEC_ID_IPV6_ADDR:
      return -1;

    case IPSEC_ID_IPV6_ADDR_SUBNET:
      return -1;

    case IPSEC_ID_IPV4_RANGE:
      return -1;

    case IPSEC_ID_IPV6_RANGE:
      return -1;

    case IPSEC_ID_DER_ASN1_DN:
      return -1;

    case IPSEC_ID_DER_ASN1_GN:
      return -1;

    case IPSEC_ID_KEY_ID:
      group = conf_get_str (section, "Key-value");
      if (!group) {
	  	log_print ("group_get_id: section %s has no \"Key-value\" tag",
		     	   section);
	  	return -1;
      }
      /*
       * Assume the Group identifier is a 32-bit number.
       */
	   /* Assume Group ID is a 32-bit number */
	  *id_sz = sizeof(unsigned int);
	  local_buf = calloc(1, *id_sz);
	  if (!local_buf) {
		  log_print("group_get_id: Couldn't get buf of size %d\n", *id_sz);
		  return -1;
	  }
	  group_id = atoi(group);
	  memcpy(local_buf, (char *)&group_id, 4);
      break;

#ifdef IEC90_5_SUPPORT
    case IPSEC_ID_IEC90_5:
	  if (iec90_5_get_id(section, id_sz, &local_buf)) {
		  log_print ("group_get_id: IEC90-5 identity error.\n");
		  return -1;
	  }
      break;
#endif

    default:
      log_print ("group_get_id: unknown ID type \"%s\" in section %s", type,
		 section);
      return -1;
    }

  *buf = local_buf;
  return 0;
}

/*
 * Out of a named section SECTION in the configuration file build an
 * ISAKMP ID payload.  Ths payload size should be stashed in SZ.
 * The caller is responsible for freeing the payload.
 */
u_int8_t *
group_build_id (char *section, size_t *sz)
{
  u_int8_t *p;
  int id;
  size_t id_sz;
  u_int8_t *buf;

  if (group_get_id (section, &id, &id_sz, &buf))
    return 0;

  *sz = ISAKMP_ID_SZ + id_sz;

  p = calloc (1, *sz);
  if (!p)
    {
      log_print ("group_build_id: calloc(%d) failed", *sz);
      return 0;
    }

  SET_ISAKMP_ID_TYPE (p, id);
  SET_ISAKMP_ID_DOI_DATA (p, (u_int8_t *)"\000\000\000");
  memcpy(&p[ISAKMP_ID_DATA_OFF], buf, id_sz); 
  free(buf);

  return p;
}

/*
 * Grow a buffer. This takes as input an old buffer location and size, and
 * another buffer which is to be added to it. It has two affects:
 * 1. Returns a new buffer with the original two buffers concatenated.
 * 2. Returns the new buffer length in the old buffer length argument.
 */
u_int8_t *
gdoi_grow_buf (u_int8_t *old_buf, size_t *old_buf_sz, 
               u_int8_t *addto_buf, size_t addto_buf_sz)
{
  u_int8_t *new_buf;
  size_t new_buf_sz = *old_buf_sz + addto_buf_sz;

  new_buf = realloc (old_buf, new_buf_sz); 
  if (!new_buf)
    {
      log_print ("gdoi_grow_buf: "
	         "realloc failed (%d) bytes", new_buf_sz);
      return 0;
    }
  memcpy((new_buf+*old_buf_sz), addto_buf, addto_buf_sz);
  *old_buf_sz = new_buf_sz;

  return new_buf;
}

/*
 * Setup a GDOI SA proto and data sections
 */
int gdoi_setup_sa (struct sa *sa, struct proto **ret_proto, 
						 int proto_type, int proto_data_size)
{
  struct proto *proto;

  /*
   * Create a proto structure and initialize some fields. 
   * We only use one proto structure -- proposals aren't negotiated.
   */
  proto = calloc (1, sizeof *proto);
  if (!proto)
    {
  	  log_error ("group_setup_gdoi_sa: calloc failure -- proto");
  	  return 1;
	}
  TAILQ_INSERT_TAIL (&sa->protos, proto, link);
  proto->proto = proto_type;
  proto->sa = sa;

  proto->data = calloc(1, proto_data_size);
  if (!proto->data)
    {
  	  log_error ("group_setup_gdoi_sa: calloc failure -- proto data");
  	  return 1;
	}

  *ret_proto = proto;
  return 0;
}

/*
 * Handle an AH/ESP TEK
 * - Allocate a gdoi_esp_tek_sa structure
 * - Allocate an ipsec_sa structure & attach to gdoi_esp_tek_sa
 * - Allocate an ipsec_proto structure & attach to gdoi_esp_tek_sa
 * - Fill 'em all up from the TEK paylaod.
 */
static int
group_decode_ipsec_tek (struct message *msg, struct sa *sa, u_int8_t *esp_tek, 
					  size_t esp_tek_len, int create_proto, 
					  int ipsec_proto_type)
{
  u_int8_t *cur_p;
  int id_type, id_len;
  struct ipsec_decode_arg ida;
  struct proto *proto;
  struct ipsec_sa *ipsec;

  /*
   * Validate the SA.
   */
  if (!sa)
    {
  	  log_error ("group_decode_ipsec_tek: No sa's in list!");
  	  goto clean_up;
	}

  if (create_proto)
  	{
  	  if (gdoi_setup_sa (sa, &proto, ipsec_proto_type, 
						 sizeof(struct ipsec_proto)))
		{
	  	  goto clean_up;
		}
	}
  else
    {
	  proto = TAILQ_LAST(&sa->protos, proto_head);
	}
  ipsec = (struct ipsec_sa *) sa->data;

  /*
   * Interpret the AH/ESP TEK header
   *  - Protocol
   */
  cur_p = esp_tek;
  ipsec->tproto = GET_GDOI_SA_TEK_ESP_IP_PROT(cur_p);


  /*
   * Get src_id fields
   */
  cur_p = esp_tek + GDOI_SA_TEK_ESP_IP_PROT_LEN;
  id_type = GET_GDOI_SA_ID_TYPE(cur_p);
  id_len = GET_GDOI_SA_ID_DATA_LEN(cur_p);
  ipsec->sport = GET_GDOI_SA_ID_PORT(cur_p);
  switch (id_type)
    {
	case IPSEC_ID_IPV4_ADDR:
	  if (id_len != 4)
		{
  	  	  log_error ("group_decode_ipsec_tek: Invalid length for src IP addr: %d",
				   id_len);
  	  	  goto clean_up;
	    }
	  ipsec->src_net = decode_32(cur_p+GDOI_SA_ID_DATA_OFF);
	  ipsec->src_mask = 0xffffffff;
	  break;
	case IPSEC_ID_IPV4_ADDR_SUBNET:
	  if (id_len != 8)
		{
  	  	  log_error ("group_decode_ipsec_tek: Invalid length for src IP subnet:"
		  			 "%d", id_len);
  	  	  goto clean_up;
	    }
	  ipsec->src_net = decode_32(cur_p+GDOI_SA_ID_DATA_OFF);
	  ipsec->src_mask = decode_32(cur_p+GDOI_SA_ID_DATA_OFF+4);
	  break;
	default:
  	  log_error ("group_decode_ipsec_tek: Unsupported src id type: %d", id_type);
  	  goto clean_up;
	}
	  
  /*
   * Get dst_id fields. Only type ID_IPV4_ADDR is reasonable.
   */
  cur_p = cur_p + GDOI_SA_ID_DATA_OFF + id_len;
  ipsec->dport = GET_GDOI_SA_ID_PORT(cur_p);
  id_len = GET_GDOI_SA_ID_DATA_LEN(cur_p);
  if (id_len != 4)
    {
  	  log_error ("group_decode_ipsec_tek: Invalid length for dst IP addr: %d",
  		          id_len);
  	  goto clean_up;
    }
  ipsec->dst_net = decode_32(cur_p + GDOI_SA_ID_DATA_OFF);
  ipsec->dst_mask = 0xffffffff;

  /* 
   * Get transform
   */
  cur_p = cur_p + GDOI_SA_ID_DATA_OFF + id_len;
  proto->id = *cur_p;
  if (msg->exchange->doi->validate_transform_id (ipsec_proto_type, 
    					proto->id) < 0) 
    {
  	  log_error ("group_decode_ipsec_tek: Invalid transform id: %d", proto->id);
  	  goto clean_up;
    }

  /*
   * Get SPI
   */
  cur_p = cur_p + 1;
  proto->spi_sz[0] = 4; /* ESP SPI length */
  proto->spi[0] = malloc(proto->spi_sz[0]);
  if (!proto->spi[0])
    {
   	  log_error ("group_decode_ipsec_tek: Malloc failure -- spi");
  	  goto clean_up;
    }
  memcpy(proto->spi[0], cur_p, proto->spi_sz[0]);
  log_print(" SPI found (SA) %u (%d) (%#x) for sa %#x", decode_32(proto->spi[0]), 
			decode_32(proto->spi[0]), decode_32(proto->spi[0]), sa);

  /*
   * Extract the attributes and stuff them into the SA.
   */
  cur_p += 4;
  
  ida.msg = msg;
  ida.sa = proto->sa;
  ida.proto = proto;
  
  attribute_map (cur_p, (esp_tek_len - (cur_p - esp_tek)), 
  				 ipsec_decode_attribute, &ida);

  return 0;
 
clean_up:
  return -1;
}

int gap_decode_attribute (u_int16_t type, u_int8_t *value, u_int16_t len,
						   void *arg)
{
  struct gdoi_kek *kek = (struct gdoi_kek *) arg;

  switch (type)
    {
	case GDOI_GAP_ACTIVATION_TIME_DELAY:
	  kek->atd = decode_16(value);
	  break;
	case GDOI_GAP_DEACTIVATION_TIME_DELAY:
	  kek->dtd = decode_16(value);
	  break;
	default:
      log_print ("gap_decode_attribute: Attribute not valid: %d", type);
	  return -1;
	}

  return 0;
}


int kek_decode_attribute (u_int16_t type, u_int8_t *value, u_int16_t len,
						   void *arg)
{
  struct gdoi_kek *kek = (struct gdoi_kek *) arg;

  switch (type)
    {
	case GDOI_ATTR_KEK_ALGORITHM:
	  kek->encrypt_alg = decode_16(value);
	  break;
	case GDOI_ATTR_SIG_HASH_ALGORITHM:
	  kek->sig_hash_alg = decode_16(value);
	  break;
	case GDOI_ATTR_SIG_ALGORITHM:
	  kek->sig_alg = decode_16(value);
	  break;
	case GDOI_ATTR_KEK_KEY_LENGTH:
	  /*
	   * Sent in bits, so convert to bytes.
	   */
	  kek->encrypt_key_len = decode_16(value) / 8;
	  break;
	case GDOI_ATTR_KEK_KEY_LIFETIME:
	  kek->kek_timer_interval = decode_32(value);
	  break;
	case GDOI_ATTR_SIG_KEY_LENGTH:
	  /*
	   * The length of the key is sent in bits.
	   */
	  kek->signature_key_modulus_size = decode_16(value);
	  break;
	case GDOI_ATTR_KEK_MANAGEMENT_ALGORITHM:
      log_print ("kek_decode_attribute: Attribute not supported: %d", type);
	  return -1;
	default:
      log_print ("kek_decode_attribute: Attribute not valid: %d", type);
	  return -1;
	}

  return 0;
}

static int
group_handle_incoming_tek (struct message *msg, u_int8_t *tek)
{
  struct exchange *exchange = msg->exchange;
  struct gdoi_exch *ie = exchange->data;
  u_int8_t specific_tek_type;
  size_t specific_tek_len;
  u_int8_t *specific_tek_p;
  int ipsec_proto_type;

  /*
   * Find the encapsulation-specific TEK payload, validate that we
   * support the specific TEK protocol (e.g., ESP), and then call 
   * the specific TEK protocol code.
   */
  specific_tek_type = GET_GDOI_SA_TEK_PROT_ID(tek);
  specific_tek_p = tek + GDOI_SA_TEK_SZ;
  specific_tek_len = GET_GDOI_GEN_LENGTH(tek) - GDOI_SA_TEK_SZ;

  /*
   * Create an SA per TEK in exchange->sa_list. The policy will be stored
   * in the SA structures.
   */ 
  if (sa_create(msg->exchange, NULL))
	{
  	  log_error ("group_handle_incoming_tek: Unable to create sa");
  	  return -1;
	}

  switch (specific_tek_type)
    {
    case GDOI_TEK_PROT_PROTO_IPSEC_ESP:
    case GDOI_TEK_PROT_PROTO_IPSEC_AH:
      /*
	   * Check the previous type. Valid types are RESERVED (indicates this is
	   * the first TEK), ESP, or AH.
	   */
	  switch (ie->teks_type) 
	  	{
		  case GDOI_TEK_PROT_RESERVED:
		  case GDOI_TEK_PROT_PROTO_IPSEC_ESP:
	    	ie->teks_type = specific_tek_type;
			break;
		  case GDOI_TEK_PROT_PROTO_IPSEC_AH:
	    	ie->teks_type = specific_tek_type;
		  	break;
		  default:
  	  		log_error ("group_handle_incoming_tek:"
             	   	   "TEKs must all be IPSEC. Previous TEK was %d", 
				   	   ie->teks_type);
  	  		return -1;
		  }
	    if (specific_tek_type == GDOI_TEK_PROT_PROTO_IPSEC_ESP)
		  {
			ipsec_proto_type = IPSEC_PROTO_IPSEC_ESP;
		  }
		else
		  {
			ipsec_proto_type = IPSEC_PROTO_IPSEC_AH;
		  }
  		if (group_decode_ipsec_tek(msg, TAILQ_LAST (&exchange->sa_list, sa_head),
								 specific_tek_p, specific_tek_len, TRUE,
								 ipsec_proto_type))
  		  {
  	  		return -1;
		  }
	    break;
#ifdef IEC90_5_SUPPORT
    case GDOI_TEK_PROT_PROTO_IEC90_5:
	  ie->teks_type = specific_tek_type;
	  switch (ie->teks_type) 
	  	{
		  case GDOI_TEK_PROT_PROTO_IEC90_5:
		  	break;
		  default:
			/*
			 * This error is for simplicity now. If both IEC90-5 and IPsec
			 * TEKs are retreived we might need to do a bit more processsing
			 * to ensure we have all the right fields for both of them.
			 */
  	  		log_error ("group_handle_incoming_tek:"
					   "Error! TEKs must all be the same! "
             	   	   "Installing IEC90-5 TEK after TEK of type %d", 
				   	   ie->teks_type);
  	  		return -1;
		  }
  		if (gdoi_iec90_5_decode_tek(msg, 
								 TAILQ_LAST (&exchange->sa_list,sa_head),
								 specific_tek_p, specific_tek_len, TRUE))
  		  {
  	  		return -1;
		  }
	    break;
#endif
#ifdef SRTP_SUPPORT
    case GDOI_TEK_PROT_PROTO_SRTP:
	  ie->teks_type = specific_tek_type;
	  switch (ie->teks_type) 
	  	{
		  case GDOI_TEK_PROT_PROTO_SRTP:
		  	break;
		  default:
  	  		log_error ("group_handle_incoming_tek:"
					   "Error! TEKs must all be the same! "
             	   	   "Installing SRTP TEK after TEK of type %d", 
				   	   ie->teks_type);
  	  		return -1;
		  }
  		if (gdoi_srtp_decode_tek(msg, TAILQ_LAST (&exchange->sa_list,sa_head),
								 specific_tek_p, specific_tek_len, TRUE))
  		  {
  	  		return -1;
		  }
	    break;
#endif
    default:
  	  	log_error ("group_handle_incoming_tek:"
             	   "Unsupported TEK type: %d", specific_tek_type);
  	  	return -1;
	}
  return 0;
}

static int
group_handle_incoming_kek (struct message *msg, u_int8_t *kek)
{
  struct exchange *exchange = msg->exchange;
  struct gdoi_exch *ie = exchange->data;
  u_int8_t *cur_p = 0;
  struct gdoi_kek *stored_kek;
  int id_type, id_len;

  /*
   * Populate the KEK fields. The received policy is kept seperate from the 
   * GDOI registration exchange because it will still be valid once the GDOI 
   * registration exchange is deleted.
   *
   * A GDOI registration message will have the ie->id_gdoi initialized, but
   * not a GDOI rekey message. 
   */
  if (ie->id_gdoi)
    {
  	  stored_kek = gdoi_get_kek(ie->id_gdoi, ie->id_gdoi_sz, 1);
	  /*
	   * Initialize the exchange name for later use.
	   */
	  if (exchange->name && !stored_kek->exchange_name)
		{
		  stored_kek->exchange_name = strdup(exchange->name);
		}
	}
  else
  	{
	  stored_kek = gdoi_get_kek_by_cookies(exchange->cookies);
	}
  if (!stored_kek)
    {
   	  log_error ("group_handle_incoming_kek: "
  			 	 "Can't allocate KEK data structure");
  	  return 1;
	}

  /*
   * Validate the protocol field.
   */
  cur_p = kek + GDOI_GEN_SZ;
  if (GET_GDOI_SA_KEK_PROTOCOL(cur_p) != IPPROTO_UDP)
    {
  	  log_error ("group_handle_incoming_kek: "
	  			 "Invalid protocol type %d", GET_GDOI_SA_KEK_PROTOCOL(cur_p));
  	  return 1;
	}

  /*
   * Get src/dst fields
   */
  cur_p += GDOI_SA_KEK_PROTOCOL_LEN;
  id_type = GET_GDOI_SA_ID_TYPE(cur_p);
  id_len = GET_GDOI_SA_ID_DATA_LEN(cur_p);
  stored_kek->sport = ntohs(GET_GDOI_SA_ID_PORT(cur_p));
  switch (id_type)
    {
	case IPSEC_ID_IPV4_ADDR:
	  if (id_len != 4)
		{
  	  	  log_error ("group_handle_incoming_kek: "
		  			 "Invalid length for src IP addr: %d", id_len);
  	  	  return 1;
	    }
	  stored_kek->src_addr = ntohl(decode_32(cur_p+GDOI_SA_ID_DATA_OFF));
	  break;
	default:
  	  log_error ("group_handle_incoming_kek: "
	  			 "Unsupported src id type: %d", id_type);
  	  return 1;
	}
  cur_p +=  GDOI_SA_ID_DATA_OFF + id_len;
  id_type = GET_GDOI_SA_ID_TYPE(cur_p);
  id_len = GET_GDOI_SA_ID_DATA_LEN(cur_p);
  stored_kek->dport = ntohs(GET_GDOI_SA_ID_PORT(cur_p));
  switch (id_type)
    {
	case IPSEC_ID_IPV4_ADDR:
	  if (id_len != 4)
		{
  	  	  log_error ("group_handle_incoming_kek: "
		  			 "Invalid length for src IP addr: %d", id_len);
  	  	  return 1;
	    }
	  stored_kek->dst_addr = ntohl(decode_32(cur_p+GDOI_SA_ID_DATA_OFF));
	  break;
	default:
  	  log_error ("group_handle_incoming_kek: "
	  			 "Unsupported src id type: %d", id_type);
  	  return 1;
	}

  /*
   * Get SPI
   * If there is already a SPI value present, put the SPI in the "next SPI", 
   * and install it later after we have the entire new policy including keys. 
   * This is necessary when a KEK is being replaced because we still need to 
   * lookup the KEK by the old cookies until we get & install the new KEK keys.
   */
  cur_p +=  GDOI_SA_ID_DATA_OFF + id_len;
  if (memcmp(stored_kek->spi, empty_cookies, KEK_SPI_SIZE))
  	{
  	  GET_GDOI_SA_KEK_END_SPI(cur_p, stored_kek->next_kek_policy.spi);
	}
  else
    {
  	  GET_GDOI_SA_KEK_END_SPI(cur_p, stored_kek->spi);
	}
 /* BEW: BUG: Need to store it in a "new" variable now.
  *      When get the keys in the KD payload, then 
  *      a) install the new SPI and its keys
  *      b) fix the exchange->cookies to match.
  */

  log_print("group_handle_incoming_kek: Got New KEK SPI: "
  	    "%02x%02x%02x%02x%02x%02x%02x%02x "
	    "%02x%02x%02x%02x%02x%02x%02x%02x",
  	    stored_kek->next_kek_policy.spi[0], stored_kek->next_kek_policy.spi[1],
	    stored_kek->next_kek_policy.spi[2], stored_kek->next_kek_policy.spi[3],
	    stored_kek->next_kek_policy.spi[4], stored_kek->next_kek_policy.spi[5],
  	    stored_kek->next_kek_policy.spi[6], stored_kek->next_kek_policy.spi[7],
	    stored_kek->next_kek_policy.spi[8], stored_kek->next_kek_policy.spi[9],
	    stored_kek->next_kek_policy.spi[10],stored_kek->next_kek_policy.spi[11],
  	    stored_kek->next_kek_policy.spi[12],stored_kek->next_kek_policy.spi[13],
	    stored_kek->next_kek_policy.spi[14],stored_kek->next_kek_policy.spi[15]
	    );

  cur_p += GDOI_SA_KEK_END_SZ;

  /*
   * Get KEK attributes.
   */
  attribute_map (cur_p, (GET_GDOI_GEN_LENGTH(kek) - (cur_p - kek)), 
  				 kek_decode_attribute, stored_kek);
  /*
   * Validate cipher attributes.
   */
  if (stored_kek->encrypt_alg == GDOI_KEK_ALG_AES) 
    {
	  /*
	   * We only support 128-bit keys. Ensure that's what we've been givne.
	   */
	  if (stored_kek->encrypt_key_len != AES128_LENGTH) 
	    {
  	  	  log_error ("group_handle_incoming_kek: "
		  			 "Unsupported AES key length: %d", 
					 stored_kek->encrypt_key_len);
  	  	  return 1;
		}
	}

  return 0;
}

static int
group_handle_incoming_gap (struct message *msg, u_int8_t *gap)
{
  struct exchange *exchange = msg->exchange;
  struct gdoi_exch *ie = exchange->data;
  u_int8_t *cur_p = 0;
  struct gdoi_kek *stored_kek;

  log_print ("group_handle_incoming_gap: Got one!\n");

  /*
   * Store the GAP policy in the stored_kek.
   */
  if (ie->id_gdoi)
    {
  	  stored_kek = gdoi_get_kek(ie->id_gdoi, ie->id_gdoi_sz, 1);
	}
  else
  	{
	  stored_kek = gdoi_get_kek_by_cookies(exchange->cookies);
	}
  if (!stored_kek)
    {
   	  log_error ("group_handle_incoming_gap: "
  			 	 "Can't allocate KEK data structure for GAP use");
  	  return 1;
	}

  /*
   * Get GAP attributes sent by the KS.
   */
  
  cur_p = gap + GDOI_GEN_SZ;
  attribute_map (cur_p, (GET_GDOI_GEN_LENGTH(gap) - GDOI_GEN_SZ), 
  				 gap_decode_attribute, stored_kek);

  return 0;
}

static int
group_fill_in_hash (struct message *msg, enum i_hash_inc i_nonce, 
		    enum r_hash_inc r_nonce)
{
  struct exchange *exchange = msg->exchange;
  struct sa *isakmp_sa = msg->isakmp_sa;
  struct ipsec_sa *isa = isakmp_sa->data;
  struct hash *hash = hash_get (isa->hash);
  struct prf *prf;
  struct payload *payload;
  u_int8_t *buf;
  int i;
  char header[80];

  /* If no SKEYID_a, we need not do anything.  */
  if (!isa->skeyid_a) {
    log_print ("group_do_hash: aborting -- no skeyid_a");
    return 0;
  }

  payload = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_HASH]);
  if (!payload)
    {
      log_print ("group_do_hash: no HASH payload found");
      return -1;
    }
  buf = payload->p;

  /* Allocate the prf and start calculating our hash */
  LOG_DBG_BUF ((LOG_MISC, 90, "group_do_hash: SKEYID_a", isa->skeyid_a,
		isa->skeyid_len));
  prf = prf_alloc (isa->prf_type, hash->type, (char *)isa->skeyid_a, 
		  		   isa->skeyid_len);
  if (!prf)
    return -1;

  prf->Init (prf->prfctx);
  LOG_DBG_BUF ((LOG_MISC, 90, "group_do_hash: message_id",
		exchange->message_id, ISAKMP_HDR_MESSAGE_ID_LEN));
  prf->Update (prf->prfctx, exchange->message_id, ISAKMP_HDR_MESSAGE_ID_LEN);

  if (i_nonce == INC_I_NONCE)
	{
	  LOG_DBG_BUF ((LOG_NEGOTIATION, 90, "group_fill_in_hash: NONCE_I_b",
	               exchange->nonce_i, exchange->nonce_i_len));
	  prf->Update (prf->prfctx, exchange->nonce_i, exchange->nonce_i_len);
	}
  if (r_nonce == INC_R_NONCE)
	{
	  LOG_DBG_BUF ((LOG_NEGOTIATION, 90, "group_fill_in_hash: NONCE_R_b",
	               exchange->nonce_r, exchange->nonce_r_len));
	  prf->Update (prf->prfctx, exchange->nonce_r, exchange->nonce_r_len);
	}


  /* Loop over all payloads after HASH.  */
  for (i = 2; i < msg->iovlen; i++)
    {
      snprintf (header, 80, "group_fill_in_hash: payload %d after HASH",
		i - 1);
      LOG_DBG_BUF ((LOG_MISC, 90, header, msg->iov[i].iov_base,
		    msg->iov[i].iov_len));
      prf->Update (prf->prfctx, msg->iov[i].iov_base, msg->iov[i].iov_len);
    }
  prf->Final (buf + ISAKMP_HASH_DATA_OFF, prf->prfctx);
  prf_free (prf);
  LOG_DBG_BUF ((LOG_MISC, 80, "group_fill_in_hash: HASH",
		       buf + ISAKMP_HASH_DATA_OFF, hash->hashsize));

  return 0;
}

static int
group_check_hash (struct message *msg, enum i_hash_inc i_nonce, 
		    enum r_hash_inc r_nonce)
{
  struct exchange *exchange = msg->exchange;
  struct sa *isakmp_sa = msg->isakmp_sa;
  struct ipsec_sa *isa = isakmp_sa->data;
  struct hash *hash = hash_get (isa->hash);
  struct payload *hashp = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_HASH]);
  size_t hashsize = hash->hashsize;
  struct prf *prf;
  u_int8_t *rest;
  size_t rest_len;
  
  if (!hashp)
    {
      log_print ("group_check_hash: no HASH payload found");
      return -1;
    }
  
  /* Allocate the prf and start calculating our HASH.  */
  LOG_DBG_BUF ((LOG_NEGOTIATION, 90, "group_check_hash: SKEYID_a",
		isa->skeyid_a, isa->skeyid_len));
  prf = prf_alloc (isa->prf_type, hash->type, (char *)isa->skeyid_a, 
		  		   isa->skeyid_len);
  if (!prf)
    return -1;

  prf->Init (prf->prfctx);
  LOG_DBG_BUF ((LOG_NEGOTIATION, 90, 
		"group_check_hash: message_id",
		exchange->message_id, ISAKMP_HDR_MESSAGE_ID_LEN));
  prf->Update (prf->prfctx, exchange->message_id, ISAKMP_HDR_MESSAGE_ID_LEN);

  if (i_nonce == INC_I_NONCE)
    {
	  LOG_DBG_BUF ((LOG_NEGOTIATION, 90, "group_check_hash: NONCE_I_b", 
	   			   exchange->nonce_i, exchange->nonce_i_len));
	  prf->Update (prf->prfctx, exchange->nonce_i, exchange->nonce_i_len);
	}
  if (r_nonce == INC_R_NONCE)
    {
	  LOG_DBG_BUF ((LOG_NEGOTIATION, 90, "group_check_hash: NONCE_R_b", 
	  			   exchange->nonce_r, exchange->nonce_r_len));
	  prf->Update (prf->prfctx, exchange->nonce_r, exchange->nonce_r_len);
	}

  rest = hashp->p + GET_ISAKMP_GEN_LENGTH (hashp->p);
  rest_len = (GET_ISAKMP_HDR_LENGTH (msg->iov[0].iov_base)
	      - (rest - (u_int8_t*)msg->iov[0].iov_base));
  LOG_DBG_BUF ((LOG_NEGOTIATION, 90,
		"group_check_hash: payloads after HASH", rest,
		rest_len));
  prf->Update (prf->prfctx, rest, rest_len);
  prf->Final ((unsigned char *)hash->digest, prf->prfctx);
  prf_free (prf);

  LOG_DBG_BUF ((LOG_NEGOTIATION, 80, "group_check_hash: computed HASH",
		(u_int8_t *)hash->digest, hashsize));
  if (memcmp (hashp->p + ISAKMP_HASH_DATA_OFF, hash->digest, hashsize) != 0)
    {
      message_drop (msg, ISAKMP_NOTIFY_INVALID_HASH_INFORMATION, 0, 1, 0);
      return -1;
    }
  /* Mark the HASH as handled.  */
  hashp->flags |= PL_MARK;

  return 0;
}

/*
 * Copy the Phase 1 cookies to the Phase 2 exchange.
 */
static int
copy_p1_cookies (struct exchange *exchange)
{
  struct exchange *p1_exchange;

  /*
   * Copy the Phase 1 identities from the phase 1 exchange in case they are
   * needed later for KE payload processing.
   */
  p1_exchange = exchange_lookup_from_icookie(exchange->cookies);
  if (p1_exchange)
    {
	  exchange->id_i_len = p1_exchange->id_i_len;
	  exchange->id_i = malloc(exchange->id_i_len);
	  if (!exchange->id_i)
	    {
		  log_print("copy_p1_cookies: "
				    "id_i malloc failed (%d bytes)", exchange->id_i_len);
		}
	  memcpy(exchange->id_i, p1_exchange->id_i, exchange->id_i_len);
	  
	  exchange->id_r_len = p1_exchange->id_r_len;
	  exchange->id_r = malloc(exchange->id_r_len);
	  if (!exchange->id_r)
	    {
		  log_print("copy_p1_cookies: "
				    "id_r malloc failed (%d bytes)", exchange->id_r_len);
		}
	  memcpy(exchange->id_r, p1_exchange->id_r, exchange->id_r_len);
    }
  else
    {
   	  log_print ("copy_p1_cookies: Couldn't find Phase 1 for this exchange.");
      return -1;
	}

  return 0;
}

/*
 * Make initial membership request to the GCKS.
 */
static int 
initiator_send_HASH_NONCE_ID (struct message *msg)
{
  struct exchange *exchange = msg->exchange;
  struct gdoi_exch *ie = exchange->data;
  u_int8_t *id;
  size_t sz;
  struct ipsec_sa *isa = msg->isakmp_sa->data;
  struct hash *hash = hash_get (isa->hash);

  /*
   * Copy the Phase 1 cookies for possible use with the KE payload.
   */
  if (copy_p1_cookies(exchange))
    {
	  return -1;
	}

  /*
   * Add HASH payload
   */
  if (!ipsec_add_hash_payload (msg, hash->hashsize)) {
	return -1;
  }
	
  /*
   * Add NONCE payload
   */
  if (exchange_gen_nonce (msg, 16)) {
	return -1;
  }

  /*
   * Add ID payload, and update the exchange structure with the group id.
   */
  id = group_build_id (exchange->name, &sz);
  if (!id) 
  	{
      log_error ("initiator_send_HASH_ID_NONCE: Group ID missing!");
	  return -1;
  	}
  LOG_DBG_BUF ((LOG_MISC, 90, "initiator_send_HASH_NONCE_ID: ID", id, sz));
  if (message_add_payload (msg, ISAKMP_PAYLOAD_ID, id, sz, 1))
	{
  	  free (id);
  	  return -1;
	}
  ie->id_gdoi_sz = sz;
  ie->id_gdoi = calloc (1, ie->id_gdoi_sz);
  memcpy(ie->id_gdoi, id, ie->id_gdoi_sz);

  if (group_fill_in_hash (msg, NO_I_NONCE, NO_R_NONCE)) {
    return -1;
  }

  return 0;
}

int
gdoi_process_SA_payload (struct message *msg)
{
  struct exchange *exchange = msg->exchange;
  struct payload *sa_p;
  u_int32_t situation;
  size_t total_p_len, cummulative_p_len;
  u_int8_t *current_p;
  struct sa *sa;
  struct proto *proto;
  u_int8_t next_p_type;


  /*
   * Evaluate the SA header.
   #   Verify DOI value is GDOI.
   #   Verify situation is 0
   #   Verify that SA Attribute Next Payload is valid
   */

  sa_p = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_SA]);
  if (!sa_p)
    {
	  log_print("gdoi_process_SA_payload: Missing SA payload!");
	  goto cleanup;
	}
  sa_p->flags |= PL_MARK;

  if (GET_GDOI_SA_DOI(sa_p->p) != GROUP_DOI_GDOI) 
     {
	   log_error ("gdoi_process_SA_payload: Wrong DOI: %d",
		     GET_GDOI_SA_DOI(sa_p->p));
	   goto cleanup;
	 }

  GET_GDOI_SA_SIT(sa_p->p, (u_int8_t *) &situation);
  if (situation != 0) 
    {
	  log_error ("gdoi_process_SA_payload: Unsupported Situation: %d",
		     GET_GDOI_SA_DOI(sa_p->p));
	  goto cleanup;
    }

  next_p_type = GET_GDOI_SA_SA_ATTR_NEXT(sa_p->p);
  if ((next_p_type != ISAKMP_PAYLOAD_SA_TEK) && 
	  (next_p_type != ISAKMP_PAYLOAD_GAP) &&
	  (next_p_type != ISAKMP_PAYLOAD_SA_KEK))
    {
	  log_error ("gdoi_process_SA_payload: Unsupported Next Attr: %d",
		    next_p_type);
	  goto cleanup;
    }

  total_p_len = GET_GDOI_GEN_LENGTH(sa_p->p);
  cummulative_p_len = ISAKMP_SA_SIT_OFF + GDOI_SIT_SIT_LEN + 
           GDOI_SA_SA_ATTR_NEXT_LEN + GDOI_SA_RES2_LEN;
  current_p = sa_p->p + cummulative_p_len;

  /* 
   * Loop through the KEK and TEK payloads. Get policy from the SA TEK 
   * payloads and stuff them away in the SA.
   */
  while (next_p_type && (cummulative_p_len < total_p_len))
	{
	  log_print ("Payload type: %d\n", next_p_type);
	  /* 
	   * Validate payload length is within normal boundaries.
	   */
	  if (GET_GDOI_GEN_LENGTH(current_p) > (total_p_len - cummulative_p_len))
	    {
		  log_print ("gdoi_process_SA_payload: "
		  			 "Payload length (%d) exceeds remaining total length (%d)",
					 GET_GDOI_GEN_LENGTH(current_p),
					 (total_p_len - cummulative_p_len));
		  goto cleanup;
		}

	  switch (next_p_type)
	    {
		case ISAKMP_PAYLOAD_SA_TEK:
		  if (group_handle_incoming_tek(msg, current_p) < 0)
		    {
			  goto cleanup;	
			}
		  break;
		
		case ISAKMP_PAYLOAD_SA_KEK:
		  if (group_handle_incoming_kek(msg, current_p) < 0)
		    {
			  goto cleanup;	
			}
		  break;

		case ISAKMP_PAYLOAD_GAP:
		  if (group_handle_incoming_gap(msg, current_p) < 0)
		    {
			  goto cleanup;	
			}
		  break;

		default:
		  log_error ("gdoi_process_SA_payload: "
		             "Unsupported SA payload type: %d", next_p_type);
		  goto cleanup;
		}
  
	  /*
   	   * Advance past this payload. Save the "next payload" type from the 
   	   * current payload first.
   	   */
  	  next_p_type = GET_GDOI_GEN_NEXT_PAYLOAD(current_p);
	  cummulative_p_len += GET_GDOI_GEN_LENGTH(current_p);
  	  current_p += GET_GDOI_GEN_LENGTH(current_p);
  	}

  return 0;

cleanup:
  /* Remove all potential protocols that have been added to the SAs.  */
  for (sa = TAILQ_FIRST (&exchange->sa_list); sa; sa = TAILQ_NEXT (sa, next))
    while ((proto = TAILQ_FIRST (&sa->protos)) != 0)
      proto_free (proto);
  return -1;
}

static int
initiator_recv_HASH_NONCE_SA (struct message *msg)
{
  struct payload *hashp;
  u_int8_t *hash, *my_hash = 0;
  size_t hash_len;
  u_int8_t *pkt = msg->iov[0].iov_base;

  hashp = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_HASH]);
  hash = hashp->p;
  hashp->flags |= PL_MARK;

  /* The HASH payload should be the first one.  */
  if (hash != pkt + ISAKMP_HDR_SZ)
    {
      /* XXX Is there a better notification type?  */
      message_drop (msg, ISAKMP_NOTIFY_PAYLOAD_MALFORMED, 0, 1, 0);
      goto cleanup;
    }
  hash_len = GET_ISAKMP_GEN_LENGTH (hash);
  my_hash = calloc (1, hash_len - ISAKMP_GEN_SZ);
  if (!my_hash)
    {
      log_error ("responder_recv_HASH_NONCE_ID: calloc (%d) failed",
		 hash_len - ISAKMP_GEN_SZ);
      goto cleanup;
    }

  /* Copy out the responder's nonce.  */
  if (exchange_save_nonce (msg))
    goto cleanup;

  if (group_check_hash(msg, INC_I_NONCE, NO_R_NONCE))
	{
      goto cleanup;
	}
 
  if (gdoi_process_SA_payload (msg))
	{
	  goto cleanup;
	}

  return 0;

cleanup:
  if (my_hash)
    free (my_hash);
  return -1;
}

int gdoi_ipsec_is_counter_mode_tek (int protocol_id, int transform_id)
{
  switch (protocol_id)
    {
	case IPSEC_PROTO_IPSEC_ESP:
  	  switch (transform_id)
    	{
		  case IPSEC_ESP_AES_CTR:
		  case IPSEC_ESP_AES_CCM_8:
		  case IPSEC_ESP_AES_CCM_12:
		  case IPSEC_ESP_AES_CCM_16:
		  case IPSEC_ESP_AES_GCM_8: case IPSEC_ESP_AES_GCM_12:
		  case IPSEC_ESP_AES_GCM_16:
	  		return 1;
	  	  default:
			break;
		}
	    break;
	case IPSEC_PROTO_IPSEC_AH:
	  switch (transform_id)
    	{
		  case IPSEC_AH_AES_128_GMAC:
		  case IPSEC_AH_AES_192_GMAC:
		  case IPSEC_AH_AES_256_GMAC:
	  		return 1;
		  default:
	  		break;
		}
	  break;
    default:
	  /* Not an error */
	  return -1;
	}

  return 0; /* Not a counter mode */

}


int gdoi_add_request_payload (struct message *msg)
{
  struct exchange *exchange = msg->exchange;
  struct sa *sa;
  struct proto *proto;
  int found_counter_modes = 0;
  int sids_needed = 0;
  int ret;
  char *sids_needed_str;
  size_t gap_sz;
  u_int8_t *gap_buf, *attr;

  /*
   * First check whether the policy given to us by the KS includes a counter
   * mode, which means we need at least one SID.
   */
  for (sa = TAILQ_FIRST (&exchange->sa_list); sa; sa = TAILQ_NEXT (sa, next))
	{
	  proto = TAILQ_FIRST (&sa->protos);
	  if (proto)
		{
		  ret = gdoi_ipsec_is_counter_mode_tek(proto->proto, proto->id);
		  switch (ret)
		    {
			case 1: 
			  found_counter_modes += 1;
			  break;
			case -1:
			  /*
			   * Probably a non-IPsec SA.
			   */
			  return 0;
			default:
			  break;
			}
		}
	}

  if (!found_counter_modes)
    {
	  /*
	   * No counter modes found -- don't need to ask for SIDs.
	   */
	  return 0;
	}

  /*
   * Check to see if the configuration said we need more than one.
   */
  sids_needed_str = conf_get_str (exchange->name, "SIDs-needed");
  if (sids_needed_str)
    {
	  sids_needed = atoi(sids_needed_str);
	  if (sids_needed > MAX_GM_SIDS)
	    {
		  log_print("gdoi_add_request_payload: Too many SIDs configured. "
				    "Configured #: %d, Max supported: %d", sids_needed,
					MAX_GM_SIDS);
	  	  return -1;
		}
	}

  if (1 == sids_needed)
	{
	  /*
	   * No need to includes a request payload. We either don't need any,
	   * or if we need just one the KS will give it to us without asking.
	   */
	  return 0;
	}

  /*
   * Add a GAP paylaod.
   */
  gap_sz = GDOI_GEN_LENGTH_OFF + GDOI_GEN_LENGTH_LEN + 4;
  gap_buf = calloc(1, gap_sz);
  if (!gap_buf)
    {
      log_print ("gdoi_get_kek_policy: calloc failed (gap_buf)");
	  return -1;
    }
  SET_GDOI_GEN_RESERVED(gap_buf, 0);
  SET_GDOI_GEN_LENGTH(gap_buf, gap_sz);
  attr = gap_buf + GDOI_GEN_LENGTH_OFF + GDOI_GEN_LENGTH_LEN;
  attr = attribute_set_basic (attr, GDOI_GAP_SENDER_ID_REQUEST, sids_needed);

  if (message_add_payload (msg, ISAKMP_PAYLOAD_GAP, gap_buf, gap_sz, 1))
    {
      return -1;
	}
  log_print("gdoi_get_kek_policy: Sending GAP payload");

  return 0;
}

static int 
initiator_send_HASH (struct message *msg)
{
  struct ipsec_sa *isa = msg->isakmp_sa->data;
  struct hash *hash = hash_get (isa->hash);

  /*
   * Add HASH payload
   */
  if (!ipsec_add_hash_payload (msg, hash->hashsize)) {
    return -1;
  }

  /*
   * Optionally add a payload to request SIDs.
   */
  if (gdoi_add_request_payload (msg)) {
	return -1;
  }

  if (group_fill_in_hash (msg, INC_I_NONCE, INC_R_NONCE)) {
    return -1;
  }

  return 0;
}

/*
 * This function take a set of keys and puts them in the passed in argument.
 * If there multiple secrecy keys they are put into the key in the same order
 * as they were sent as attributes.
 */
int
gdoi_decode_kd_kek_attribute (u_int16_t type, u_int8_t *value, u_int16_t len,
                          void *arg)
{
  struct gdoi_kek *stored_kek = (struct gdoi_kek *) arg;
  u_int16_t exp_len;

  switch (type)
    {
	case GDOI_ATTR_KD_KEK_SECRECY_KEY:
	  log_print("Found a KEK secrecy attribute");
	  /*
	   * If there was already allocated memory then we must have already
	   * gotten  KEK keys and IV. We don't really know if the new iv & 
	   * keys are the same length as the old ones, so need to free and 
	   * re-malloc rather than re-use.
	   */
	  if (stored_kek->encrypt_iv) 
	  	{
		  log_print("decode_kd_kek_attribute: Replacing KEK IV and keys.");
		  free(stored_kek->encrypt_iv);
		  free(stored_kek->encrypt_key);
		}
	  /*
	   * Validate that we got adequate keys for the  algorithm.
	   */
	  switch (stored_kek->encrypt_alg)
	    {
		case GDOI_KEK_ALG_3DES:
		  /*
		   * IV is pre-prepended before the DES keys.
		   */
		  exp_len = 4 * DES_LENGTH;
		
		  if (len != exp_len)
		  	{
	      	  log_error ("decode_kd_kek_attribute: "
			         	 "Wrong key length! Expected:%d, Actual:%d", 
						 exp_len, len);
		  	  return -1;
			}
		  /*
		   * Store the IV
		   */
		  stored_kek->encrypt_iv = malloc(DES_LENGTH);
		  if (!stored_kek->encrypt_iv)
		  	{
	     	  log_error ("decode_kd_kek_attribute: malloc failed (%d)", 
					     DES_LENGTH);
			  return -1;
			}
		  memcpy(stored_kek->encrypt_iv, value, DES_LENGTH);
		  /*
		   * Store the keys
		   */
		  stored_kek->encrypt_key = malloc(3 * DES_LENGTH);
		  if (!stored_kek->encrypt_key)
		  	{
	     	  log_error ("decode_kd_kek_attribute: malloc failed (%d)", 
					     3 * DES_LENGTH);
			  return -1;
			}
		  memcpy((stored_kek->encrypt_key), (value+DES_LENGTH), 3 * DES_LENGTH);
		  break;
		case GDOI_KEK_ALG_AES:
		  /*
		   * IV is pre-prepended before the AES key.
		   */
		  exp_len = 2 * stored_kek->encrypt_key_len;
		
		  if (len != exp_len)
		  	{
	      	  log_error ("decode_kd_kek_attribute: "
			         	 "Wrong key length! Expected:%d, Actual:%d", 
						 exp_len, len);
		  	  return -1;
			}
		  /*
		   * Store the IV
		   */
		  stored_kek->encrypt_iv = malloc(stored_kek->encrypt_key_len);
		  if (!stored_kek->encrypt_iv)
		  	{
	     	  log_error ("decode_kd_kek_attribute: malloc failed (%d)", 
					  		stored_kek->encrypt_key_len);
			  return -1;
			}
		  memcpy(stored_kek->encrypt_iv, value, stored_kek->encrypt_key_len);
		  /*
		   * Store the key
		   */
		  stored_kek->encrypt_key = malloc(stored_kek->encrypt_key_len);
		  if (!stored_kek->encrypt_key)
		  	{
	     	  log_error ("decode_kd_kek_attribute: malloc failed (%d)", 
					  		stored_kek->encrypt_key_len);
			  return -1;
			}
		  memcpy((stored_kek->encrypt_key), (value+stored_kek->encrypt_key_len),
				  stored_kek->encrypt_key_len);
		  break;
		default:
      	  log_error ("decode_kd_kek_attribute: "
		         	 "Unknown KEK secrecy algorithm: %d", type);
	  	  return -1;
		}
	  break;

	case GDOI_ATTR_KD_KEK_SIGNATURE_KEY:
	  log_print("Found a KEK signature attribute");
	 
	  /*
	   * Key length may vary, so can't validate it for certain. But we
	   * can estimate an upper bound.
	   */
	  if (len > MAX_PUBKEY_SIZE)
	  	{
     	  log_error ("decode_kd_kek_attribute: sig public key too large (%d)",
		  			 len);
		  return -1;
		}
	  if (gdoi_store_pubkey (value, len, stored_kek) < 0)
	  	{
     	  log_error ("decode_kd_kek_attribute: Storing public key failed (%d)");
		  return -1;
		}
	  break;

	default:
      log_error ("decode_kd_kek_attribute: "
	        	 "Unknown attribute: %d", type);
	  return -1;
	}

	return 0;
}

/*
 * This function take a set of keys and puts them in the passed in argument.
 * If there multiple secrecy keys they are put into the key in the same order
 * as they were sent as attributes.
 */
int
gdoi_decode_kd_tek_attribute (u_int16_t type, u_int8_t *value, u_int16_t len,
                          void *arg)
{
  struct gdoi_kd_decode_arg *keys = (struct gdoi_kd_decode_arg *) arg;

  switch (type)
    {
	case GDOI_ATTR_KD_TEK_SECRECY_KEY:
	  log_print("Found a secrecy attribute");
	  keys->sec_key = malloc(len);
  	  keys->sec_key_sz = len;
	  memcpy(keys->sec_key, value, len);
	  break;

	case GDOI_ATTR_KD_TEK_INTEGRITY_KEY:
	  log_print("Found an integrity attribute");
	  keys->int_key = malloc(len);
	  keys->int_key_sz = len;
	  memcpy(keys->int_key, value, len);
	  break;

	case GDOI_ATTR_KD_TEK_SOURCE_AUTH_KEY:
      log_error ("decode_kd_tek_attribute: "
		         "Source authentication not yet supported");
	  return -1;
	  break;

#ifdef IEC90_5_SUPPORT
	case IEC90_5_KD_61850_ETHERENT_GOOSE_OR_SV:
	case IEC90_5_KD_61850_90_5_SESSION:
	case IEC90_5_KD_61850_8_1_ISO9506:
	case IEC90_5_KD_61850_UDP_IP_AGGR:
	case IEC90_5_KD_61850_UDP_MNGT:
	  log_print("Found an IEC 90-5 attribute");
	  keys->custom_kd_payload_type = type;
	  keys->custom_kd_payload = malloc(len);
	  keys->custom_kd_payload_sz = len;
	  memcpy(keys->custom_kd_payload, value, len);
	  break;
#endif

	default:
      log_error ("decode_kd_tek_attribute: "
		         "Unknown attribute: %d", type);
	  return -1;
	}
	return 0;
}

static int 
install_kek_keys (struct message *msg, u_int8_t **buf)
{
  struct exchange *exchange = msg->exchange;
  struct gdoi_exch *ie = exchange->data;
  size_t kd_spi_sz;
  u_int8_t *kd_spi;
  u_int8_t *key_packet = *buf;
  u_int8_t *attr_p;
  size_t attr_len;
  struct gdoi_kek *stored_kek;

  /*
   * Find the KEK policy, and validate that the SPI is the same.
   *
   * A GDOI registration message will have the ie->id_gdoi initialized, but
   * not a GDOI rekey message. 
   */
  if (ie->id_gdoi)
    {
  	  stored_kek = gdoi_get_kek(ie->id_gdoi, ie->id_gdoi_sz, 0);
	}
  else
  	{
	  stored_kek = gdoi_get_kek_by_cookies(exchange->cookies);
	}
  if (!stored_kek)
    {
      log_print ("install_kek_keys: "
	         	 "KEK policy missing from exchange");
	  return -1;
	}
  kd_spi_sz = GET_GDOI_KD_PAK_SPI_SIZE(key_packet);
  kd_spi = key_packet + GDOI_KD_PAK_SPI_SIZE_OFF + GDOI_KD_PAK_SPI_SIZE_LEN;
  if ((kd_spi_sz != KEK_SPI_SIZE) || 
  	  memcmp(stored_kek->spi, kd_spi, KEK_SPI_SIZE))
	{
	  log_print ("install_kek_keys: SPI mismatch!");
	  return -1;
	}

	/*
	 * Find the key attributes and stick them into the kek structure.
	 */
	attr_p = key_packet + GDOI_KD_PAK_SPI_SIZE_OFF +
						GDOI_KD_PAK_SPI_SIZE_LEN + kd_spi_sz;
	attr_len = GET_GDOI_KD_PAK_LENGTH(key_packet) -
						   GDOI_KD_PAK_SPI_SIZE_LEN - kd_spi_sz;
  	attribute_map (attr_p, attr_len, gdoi_decode_kd_kek_attribute, 
							   (void *)stored_kek);

  *buf += GET_GDOI_KD_PAK_LENGTH(key_packet);

  /*
   * We now have everything we need in order to listen for rekey messages.
   * So, stuff the SPI into current SPI, adjust the cookies in the exchange
   * to match the SPI, and start listening.
   */
  memset(empty_cookies, 0, KEK_SPI_SIZE);
  if (memcmp(stored_kek->next_kek_policy.spi, empty_cookies, KEK_SPI_SIZE))
  	{
  	  memcpy(stored_kek->spi, &stored_kek->next_kek_policy.spi, KEK_SPI_SIZE);
	}
  gdoi_rekey_listen (stored_kek);

  return 0;
}

/*
 * Concatonate the encryption and auth keys as keymat[0] in an IPSEC
 * proto structure.
 */
static int
stuff_tek_keys (struct gdoi_kd_decode_arg *keys, struct ipsec_proto *iproto)
{
  if (keys->int_key)
    {
  	  if (keys->sec_key)
    	{
	  	  /*
	   	   * Combine the keys into one blob.
	   	   */
  	  	  keys->sec_key = gdoi_grow_buf(keys->sec_key, 
  								    	&keys->sec_key_sz, 
  						  		    	keys->int_key, 
  								    	keys->int_key_sz);
  	  	  free(keys->int_key);
		}
	  else
	  	{
	  	  /*
	   	   * There is no sec_key in this case, so overload the field.
	   	   */
	  	  keys->sec_key = keys->int_key;
		}
	}
  iproto->keymat[0] = keys->sec_key;

  return 0;
}

/*
 * Seperate the encryption and auth keys from keymat[0] in an IPSEC
 * proto structure.
 */
int
gdoi_ipsec_get_tek_keys (struct gdoi_kd_decode_arg *keys, struct proto *proto)
{
 struct ipsec_proto *iproto = (struct ipsec_proto *) proto->data;

  switch (proto->proto)
    {
	case IPSEC_PROTO_IPSEC_ESP:
  	  keys->sec_key_sz = ipsec_esp_enckeylength(proto);
  	  keys->int_key_sz = ipsec_esp_authkeylength(proto);
	  break;
	case IPSEC_PROTO_IPSEC_AH:
	  keys->sec_key_sz = 0;
  	  keys->int_key_sz = ipsec_ah_keylength(proto); 
	  break;
	default:
      log_error ("gdoi_ipsec_get_tek_keys: "
		         "Unknown IPsedc protocol: %d", proto->proto);
	  return -1;
	}

  if (keys->sec_key_sz)
  	{
  	  keys->sec_key = malloc(keys->sec_key_sz);
  	  if (!keys->sec_key)
  		{
	  	  return -1;
		}
  	  memcpy(keys->sec_key, iproto->keymat[0], keys->sec_key_sz);
	}
 
  if (keys->int_key_sz)
  	{
  	  keys->int_key = malloc(keys->int_key_sz);
  	  if (!keys->int_key)
  		{
	  	  return -1;
		}
  	  memcpy(keys->int_key, (iproto->keymat[0]+keys->sec_key_sz), 
	  		 keys->int_key_sz);
	}

  return 0;
}

static int 
install_tek_keys (struct message *msg, u_int8_t **buf)
{
  struct sa *sa;
  struct exchange *exchange = msg->exchange;
  struct gdoi_exch *ie = exchange->data;
  struct proto *proto;
  struct ipsec_proto *iproto = 0;
  u_int32_t kd_spi_sz;
  u_int8_t *kd_spi = 0;
  u_int32_t exp_keymat_len;
  u_int8_t *key_packet = *buf;
  u_int8_t *attr_p;
  size_t attr_len;
  struct gdoi_kd_decode_arg keys;
  int found_spi = 0;
#ifdef SRTP_SUPPORT
  struct srtp_proto *sproto;
#endif

  /*
   * Match SPI in the key packet to a proto in the sa_list.
   * For the SA structures
   *  For all Group SA structures
   *   Do the protocol-specific search (See below)
   */
  for (sa = TAILQ_FIRST (&msg->exchange->sa_list); sa; 
  	   sa = TAILQ_NEXT (sa, next))
    {
	  if (!sa->data)
	    {
      	  log_print ("install_tek_keys: "
		         	 "SA DOI specific data missing");
      	  return -1;
		}

	  /*
	   * Common KD paylaod handling.
	   */
				proto = TAILQ_FIRST (&sa->protos);
				if (!proto)
				  {
      	  	  		log_print ("install_tek_keys: "
		         	 	 	   "TEK proto data missing");
      	  	  		return -1;
				  }
				if (!proto->spi[0])
				  {
      	  	  		log_print ("install_tek_keys: "
		         	 	 	   "TEK proto SPI missing");
      	  	  		return -1;
				  }
				kd_spi_sz = GET_GDOI_KD_PAK_SPI_SIZE(key_packet);
				kd_spi = key_packet + GDOI_KD_PAK_SPI_SIZE_OFF +
						 GDOI_KD_PAK_SPI_SIZE_LEN;
				if (proto->spi_sz[0] != (u_int8_t) kd_spi_sz)
				  {
					/* Might indicate an error, so log it */
      	  	  		log_print ("install_tek_keys: Mismatching spi size!");
					continue;
				  }
				if (memcmp(proto->spi[0], kd_spi, proto->spi_sz[0]))
				  {
					/* No match. Try the next one */
					continue;
				  }
				/*
				 * SPIs match!
				 */
				switch(kd_spi_sz) {
				  case 1:
  					log_print(" SPI found (SA) %u (%#x) for sa %#x", 
		    					*kd_spi, *kd_spi, sa);
					found_spi = 1;
					break;
				  case 2:
					log_print(" SPI found (KD) %u (%#x) for sa %#x", 
								decode_16(kd_spi), decode_16(kd_spi), sa);
					found_spi = 1;
					break;
				  case 4:
					log_print(" SPI found (KD) %u (%#x) for sa %#x", 
								decode_32(kd_spi), decode_32(kd_spi), sa);
					found_spi = 1;
					break;
				  default:
				  	log_print ("install_tek_keys: "
							   "Unsupported spi size: %d", kd_spi_sz);
					break;
				  }

	  /*
	   * Find the length of the keying material based on the TEK type.
	   */
	  switch (ie->teks_type)
		{
		  case GDOI_TEK_PROT_PROTO_IPSEC_ESP:
		  case GDOI_TEK_PROT_PROTO_IPSEC_AH:
				/*
				 * Install the keys. The SAs will be installed in the kernel
				 * in gdoi_finalize_exchange().
				 */
  				iproto = (struct ipsec_proto *) proto->data;
				if (!iproto)
				  {
  	  				log_print ("install_tek_keys:" "Missing iproto ptr");
					return -1;
				  }
				/*
				 * Get the expected length of the keys for malloc. Verify
				 * that the byte count matches when we get the keys.
				 */
  				switch (proto->proto)
    			  {
				  case IPSEC_PROTO_IPSEC_ESP:
					exp_keymat_len = ipsec_esp_enckeylength (proto) +
											ipsec_esp_authkeylength (proto);
	  				break;
				  case IPSEC_PROTO_IPSEC_AH:
  	  				exp_keymat_len = ipsec_ah_keylength(proto); 
	  				break;
				  default:
      				log_error ("install_tek_keys: "
		         		"Unknown IPsec protocol: %d", proto->proto);
	  				return -1;
				  }
				break;
#ifdef IEC90_5_SUPPORT
    	  case GDOI_TEK_PROT_PROTO_IEC90_5:
				/*
				 *  Keys are returned in a private attribute structure.
				 *  Trying to check the key length here isn't valuables.
				 */
				exp_keymat_len = 0;
				break;
#endif
#ifdef SRTP_SUPPORT
    	  case GDOI_TEK_PROT_PROTO_SRTP:
				/*
				 * Install the keys. The SAs will be installed in the kernel
				 * in gdoi_finalize_exchange().
				 */
  				sproto = (struct srtp_proto *) proto->data;
				if (!sproto)
				  {
  	  				log_print ("install_tek_keys:" "Missing sproto ptr");
					return -1;
				  }
				/*
				 * Get the expected length of the keys for malloc. Verify
				 * that the byte count matches when we get the keys.
				 */
				exp_keymat_len = sproto->master_key_len + 
								 sproto->master_salt_key_len;
				break;
#endif
		  default:
      			log_error ("install_tek_keys: "
		         		"Unknown TEK type: %d", proto->proto);
	  			return -1;
		}
				/*
				 * Find the key attributes and stick them into keymat.
				 */
				attr_p = key_packet + GDOI_KD_PAK_SPI_SIZE_OFF +
						GDOI_KD_PAK_SPI_SIZE_LEN + kd_spi_sz;
				attr_len = GET_GDOI_KD_PAK_LENGTH(key_packet) -
						   GDOI_KD_PAK_SPI_SIZE_OFF -
						   GDOI_KD_PAK_SPI_SIZE_LEN - kd_spi_sz;
				memset((void *)&keys, 0, sizeof(struct gdoi_kd_decode_arg));
  	  			attribute_map (attr_p, attr_len, gdoi_decode_kd_tek_attribute, 
							   (void *)&keys);
				/*
				 * Verify that the key server sent the right amount of key
				 * material.
				 */
  				if ((keys.sec_key_sz + keys.int_key_sz) != exp_keymat_len)
    			  {
	  				log_print ("install_tek_keys:"
     	   	     			   "Wrong key length! Expected: %d, Actual: %d",
  			  	  			   exp_keymat_len, 
							   keys.sec_key_sz + keys.int_key_sz);
  	  				free(keys.sec_key);
  		  			free(keys.int_key);
  	  				return -1;
  	  			  }
	  switch (ie->teks_type)
		{
		  case GDOI_TEK_PROT_PROTO_IPSEC_ESP:
		  case GDOI_TEK_PROT_PROTO_IPSEC_AH:
				if (stuff_tek_keys(&keys, iproto))
				  {
				  	return -1;
				  }
	    		break;
#ifdef IEC90_5_SUPPORT
    	  case GDOI_TEK_PROT_PROTO_IEC90_5:
			if (gdoi_iec90_5_install_keys(proto, &keys))
			  {
				return -1;
			  }
			break;
#endif
#ifdef SRTP_SUPPORT
    	  case GDOI_TEK_PROT_PROTO_SRTP:
			if (gdoi_srtp_install_keys(proto, &keys))
			  {
				return -1;
			  }
			break;
#endif
    		  default:
  	  			log_print ("install_tek_keys:"
             	   		   "Unsupported TEK type: %d", ie->teks_type);
  	  			return -1;
		}
	}

    *buf += GET_GDOI_KD_PAK_LENGTH(key_packet);
	return 0;
}


/*
 * This function take a set of keys and puts them in the passed in argument.
 * If there multiple secrecy keys they are put into the key in the same order
 * as they were sent as attributes.
 */
int
gdoi_decode_kd_sid_attribute (u_int16_t type, u_int8_t *value, u_int16_t len,
                          void *arg)
{
  struct gdoi_kek *stored_kek = (struct gdoi_kek *) arg;
  int found_length = 0;

  /*
   * New SID values override an pre-existing one. This is important: the old
   * ones may be re-assigned by the KS for new SAs.
   */
  stored_kek->number_sids = 0;

  switch (type)
    {
	case GDOI_ATTR_KD_SID_NUM_BITS:
	  log_print("Found a SID length (in # of bits) attribute");
	  if (found_length)
	    {
		  log_print("gdoi_decode_kd_sid_attribute: "
				    "Multiple SID length attributes received");
		  return -1;
		}
	  stored_kek->sid_length = decode_16(value);
	  found_length = 1;
	  break;

	case GDOI_ATTR_KD_SID_VALUE:
	  log_print("Found a SID value attribute");
	  /*
	   * We only support certain lengths to decode the value.
	   */
	  if (stored_kek->number_sids < MAX_GM_SIDS)
	    {
	      switch (len)
			{
			case 2:
		  	  stored_kek->sids[stored_kek->number_sids] = decode_16 (value);
		  	  break;
			case 4:
		  	  stored_kek->sids[stored_kek->number_sids] = decode_32 (value);
		  	  break;
			default:
		  	  log_error ("decode_kd_sid_attribute: Unsupported SID value "
					     "length: %d", len);
			  return -1;
			}
	  	  stored_kek->number_sids += 1;
	    }
	  else
	  {
		log_print("Warning: Too many SID value attributes - can only store %d",
				  MAX_GM_SIDS);
	  }
	  break;

	default:
      log_error ("decode_kd_sid_attribute: "
		         "Unknown attribute: %d", type);
	  return -1;
	}
	return 0;
}

static int 
install_sid_values (struct message *msg, u_int8_t **buf)
{
  struct exchange *exchange = msg->exchange;
  struct gdoi_exch *ie = exchange->data;
  size_t kd_spi_sz;
  u_int8_t *key_packet = *buf;
  u_int8_t *attr_p;
  size_t attr_len;
  struct gdoi_kek *stored_kek;

  /*
   * Find the place to store group policy first.
   */
  stored_kek = gdoi_get_kek(ie->id_gdoi, ie->id_gdoi_sz, 0);
  if (!stored_kek)
    {
	  log_print("install_sid_values: No place to store group policy!");
	  return -1;
	}
	  
  /*
   * SPI size shold be zero.
   */
  kd_spi_sz = GET_GDOI_KD_PAK_SPI_SIZE(key_packet);
  if (0 != kd_spi_sz)
    {
	  log_print("install_sid_values: Expected SPI size 0, got %d", kd_spi_sz);
	  return -1;
	}

	/*
	 * Find the key attributes and stick them into keymat.
	 */
	attr_p = key_packet + GDOI_KD_PAK_SPI_SIZE_OFF + GDOI_KD_PAK_SPI_SIZE_LEN +
			 kd_spi_sz;
	attr_len = GET_GDOI_KD_PAK_LENGTH(key_packet) - GDOI_KD_PAK_SPI_SIZE_OFF -
			   GDOI_KD_PAK_SPI_SIZE_LEN - kd_spi_sz;
  	attribute_map (attr_p, attr_len, gdoi_decode_kd_sid_attribute, 
							   (void *)stored_kek);

    *buf += GET_GDOI_KD_PAK_LENGTH(key_packet);

	/*
	 * Verify if we got as many SIDs as we needed (based on configuration).
	 */
	if (stored_kek->number_sids < stored_kek->number_sids_needed)
	  {
		log_print("install_sid_values: WARNING: Needed %s SIDs, got %s.",
				  stored_kek->number_sids_needed, stored_kek->number_sids);
	  }

	return 0;
}

int
gdoi_process_KD_payload (struct message *msg)
{
  struct exchange *exchange = msg->exchange;
  struct payload *kdp;
  u_int8_t *buf;
  size_t num_key_packets;
  u_int32_t type;
  int i;

  kdp = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_KD]);
  if (kdp)
    {
  	  kdp->flags |= PL_MARK;
      num_key_packets = GET_GDOI_KD_NUM_PACKETS(kdp->p);
      log_print ("GOT # of packets: %d", num_key_packets);

	  buf = kdp->p + GDOI_KD_RES2_OFF + GDOI_KD_RES2_LEN;
	  for (i=0; i<num_key_packets; i++) 
	    {
		  type = GET_GDOI_KD_PAK_KD_TYPE(buf);
		  switch (type)
		    {
			  case GDOI_KD_TYPE_KEK:
				if (install_kek_keys(msg, &buf) < 0)
				  {
      				return -1;
				  }
				break;
			  case GDOI_KD_TYPE_TEK:
				if (install_tek_keys(msg, &buf) < 0)
				  {
      				return -1;
				  }
				break;
			  case GDOI_KD_TYPE_SID:
				/*
				 * Only accept SIDs in a GDOI registration ("PULL_MODE")
				 * exchange!! They are unique to a particular GM.
				 */
  				if (exchange->type == GDOI_EXCH_PULL_MODE)
				  {
					if (install_sid_values(msg, &buf) < 0)
				  	  {
      					return -1;
				  	  }
				  }
				else
				  {
					log_print("gdoi_process_KD_payload: Received SIDs in "
							  "a GDOI_PUSH exchange, which is invalid!");
					return -1;
				  }
				break;
			  default:
      			log_print ("gdoi_process_KD_payload: "
				           "Unsupported KD Payload type (%d)", type);
      			return -1;
			}
		}
    }
  else
  {
	log_print("gdoi_process_KD_payload: Missing KD payload!");
	return -1;
  }

  return 0;
}

static int initiator_recv_HASH_SEQ_KD (struct message *msg)
{
  struct gdoi_exch *ie = msg->exchange->data;
  struct payload *hashp, *seqp;
  u_int8_t *hash;
  u_int8_t *pkt = msg->iov[0].iov_base;
  u_int32_t seq;
  struct gdoi_kek *stored_kek = 0;

  hashp = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_HASH]);
  hash = hashp->p;
  hashp->flags |= PL_MARK;

  /* The HASH payload should be the first one.  */
  if (hash != pkt + ISAKMP_HDR_SZ)
    {
      /* XXX Is there a better notification type?  */
      message_drop (msg, ISAKMP_NOTIFY_PAYLOAD_MALFORMED, 0, 1, 0);
      goto cleanup;
    }
  if (group_check_hash(msg, INC_I_NONCE, INC_R_NONCE))
    goto cleanup;

  /*
   * Handle SEQ
   */
  seqp = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_SEQ]);
  if (seqp)
    {
  	stored_kek = gdoi_get_kek(ie->id_gdoi, ie->id_gdoi_sz, 0);
  	if (!stored_kek)
      {
      	log_print ("initiator_recv_HASH_SEQ_KD: "
	         	 	"group policy structure missing from exchange");
	  	return -1;
	  }
  	  seqp->flags |= PL_MARK;
      seq = GET_GDOI_SEQ_SEQ_NUM(seqp->p);
      log_print ("GOT SEQ # of: %d (PULL)", seq);
  	  if (stored_kek->encrypt_alg)
	    {
	  	  stored_kek->current_seq_num = seq;
		}
	  else
    	{
      	  log_print ("initiator_recv_HASH_SEQ_KD: "
	         	 	 "SEQ sent without KEK. Ignoring sequence number");
		}
    }
  else
	{
	  /*
	   * Complain about a missing SEQ if we received a KEK (including the
	   * KEK encryption algorithm).
	   */
	  if (stored_kek && stored_kek->encrypt_alg)
	  	{
		  log_print("initiator_recv_HASH_SEQ_KD: Missing SEQ payload!");
		  goto cleanup;
		}
	}

  
  /*
   * Handle KD
   */
  if (gdoi_process_KD_payload (msg))
  	{
	  goto cleanup;
	}

  return 0;

cleanup:
  return -1;
}

static int responder_recv_HASH_NONCE_ID (struct message *msg)
{
  struct payload *idp;
  struct sa *sa;
  struct exchange *exchange = msg->exchange;
  struct gdoi_exch *ie = exchange->data;
  struct proto *proto;

  /*
   * Copy the Phase 1 cookies for possible use with the KE payload.
   */
  if (copy_p1_cookies(exchange))
    {
	  return -1;
	}

  if (group_check_hash(msg, NO_I_NONCE, NO_R_NONCE))
    goto cleanup;

  /* Copy out the initiator's nonce.  */
  if (exchange_save_nonce (msg))
    goto cleanup;
  
  /* Handle ID payload.  */
  idp = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_ID]);
  if (idp)
    {
      ie->id_gdoi_sz = GET_ISAKMP_GEN_LENGTH (idp->p);
      ie->id_gdoi = calloc (1, ie->id_gdoi_sz);
      if (!ie->id_gdoi)
		{
	  	  log_print ("responder_recv_HASH_NONCE_ID: malloc (%d) failed",
		     		 ie->id_gdoi_sz);
	  	  return -1;
		}
      memcpy (ie->id_gdoi, idp->p, ie->id_gdoi_sz);
      idp->flags |= PL_MARK;
      LOG_DBG_BUF ((LOG_MISC, 90,
		     "responder_recv_HASH_NONCE_ID: ID",
		     ie->id_gdoi + ISAKMP_GEN_SZ, ie->id_gdoi_sz -
		     ISAKMP_GEN_SZ));

    }
  else
  {
	log_print("responder_recv_HASH_NONCE_ID: Missing ID payload!");
	goto cleanup;
  }

  return 0;

cleanup:
  /* Remove all potential protocols that have been added to the SAs.  */
  for (sa = TAILQ_FIRST (&exchange->sa_list); sa; sa = TAILQ_NEXT (sa, next))
    while ((proto = TAILQ_FIRST (&sa->protos)) != 0)
      proto_free (proto);
  return -1;
}

/*
 * Out of a named section SECTION in the configuration file find out
 * the network address and mask as well as the ID type.  Put the info
 * in the areas pointed to by ADDR, MASK and ID respectively.  Return
 * 0 on success and -1 on failure.
 *
 * Taken from ipsec_get_id(). Added support for getting a port and returning
 * it as the "port" argument.
 */
int
gdoi_get_id (char *section, int *id, struct in_addr *addr,
	      struct in_addr *mask, uint16_t *port)
{
  char *type, *address, *netmask, *port_string;

  type = conf_get_str (section, "ID-type");
  if (!type)
    {
      log_print ("gdoi_get_id: section %s has no \"ID-type\" tag", section);
      return -1;
    }

  *id = constant_value (ipsec_id_cst, type);
  switch (*id)
    {
    case IPSEC_ID_IPV4_ADDR:
      address = conf_get_str (section, "Address");
      if (!address)
		{
	  	  log_print ("gdoi_get_id: section %s has no \"Address\" tag",
		     		 section);
	  	  return -1;
		}

      if (!inet_aton (address, addr))
		{
	  	  log_print ("gdoi_get_id: invalid address %s in section %s", section,
		     		 address);
	  	  return -1;
		}
   
	  mask->s_addr = 0xffffffff;
      break;

#ifdef notyet
    case IPSEC_ID_FQDN:
      return -1;

    case IPSEC_ID_USER_FQDN:
      return -1;
#endif

    case IPSEC_ID_IPV4_ADDR_SUBNET:
      address = conf_get_str (section, "Network");
      if (!address)
	{
	  log_print ("gdoi_get_id: section %s has no \"Network\" tag",
		     section);
	  return -1;
	}

      if (!inet_aton (address, addr))
	{
	  log_print ("gdoi_get_id: invalid section %s network %s", section,
		     address);
	  return -1;
	}

      netmask = conf_get_str (section, "Netmask");
      if (!netmask)
	{
	  log_print ("gdoi_get_id: section %s has no \"Netmask\" tag",
		     section);
	  return -1;
	}

      if (!inet_aton (netmask, mask))
	{
	  log_print ("gdoi_id_build: invalid section %s network %s", section,
		     netmask);
	  return -1;
	}
      break;

#ifdef notyet
    case IPSEC_ID_IPV6_ADDR:
      return -1;

    case IPSEC_ID_IPV6_ADDR_SUBNET:
      return -1;

    case IPSEC_ID_IPV4_RANGE:
      return -1;

    case IPSEC_ID_IPV6_RANGE:
      return -1;

    case IPSEC_ID_DER_ASN1_DN:
      return -1;

    case IPSEC_ID_DER_ASN1_GN:
      return -1;

    case IPSEC_ID_KEY_ID:
      return -1;
#endif
    }
      
  port_string = conf_get_str (section, "Port");
  if (!port_string)
    {
      log_print ("gdoi_get_id: section %s has no \"Port\" tag",
   	         section);
      *port = 0;
    } 
  else 
    {
  	  *port = atoi(port_string);
    }

  return 0;
}

/*
 * Create the ID fields of a TEK payload. This payload size should be 
 * stashed in sz. The caller is responsible for freeing the payload.
 */
u_int8_t *
gdoi_build_tek_id_internal (int id_type, struct in_addr addr, 
							struct in_addr mask, uint16_t port, size_t *sz)
{
  u_int8_t *p;
  size_t id_payload_len;
      
  /*
   * Initialize size to the size of the structure except for the 
   * identity data.
   */
  *sz = GDOI_SA_ID_DATA_LEN_OFF + GDOI_SA_ID_DATA_LEN_LEN;
  switch (id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
	  id_payload_len = sizeof addr;
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
	  id_payload_len = sizeof addr * 2;
      break;
    default:
      log_print ("gdoi_build_id: "
                 "Unsupported ID type (%d) for ESP", id_type);
      return 0;
    }
  *sz += id_payload_len;
  p = calloc(1, *sz);
  if (!p)
    {
      log_error ("gdoi_build_id: "
	             "calloc(%d) failed", *sz);
	  return 0;
    }

  /*
   * Fill in the id structure
   */
  SET_GDOI_SA_ID_TYPE(p, id_type);
  SET_GDOI_SA_ID_PORT(p, htons(port));
  SET_GDOI_SA_ID_DATA_LEN(p, id_payload_len);
  switch (id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
      encode_32 (p + GDOI_SA_ID_DATA_OFF, htonl (addr.s_addr));
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
      encode_32 (p + GDOI_SA_ID_DATA_OFF, htonl (addr.s_addr));
      encode_32 (p + GDOI_SA_ID_DATA_OFF + sizeof addr, 
	  			 ntohl (mask.s_addr));
      break;
    default:
      log_print ("gdoi_build_id: "
	         "Unsupported ID type (%d) for ESP", id_type);
      free (p);
      return 0;
	}

  return p;
}

/*
 * Out of a named section SECTION in the configuration file the ID fields
 * of a TEK payload. The caller is responsible for freeing the payload.
 */
u_int8_t *
gdoi_build_tek_id (char *section, size_t *sz)
{
  struct in_addr addr, mask;
  uint16_t port;
  int id_type;
      
  if (gdoi_get_id (section, &id_type, &addr, &mask, &port))
    {
      return 0;
    }
  return gdoi_build_tek_id_internal (id_type, addr, mask, port, sz);  
}

/*
 * Out of an SA build the ID fields of a TEK payload. The caller is 
 * responsible for freeing the payload.
 */
u_int8_t *
gdoi_build_tek_id_from_sa (struct sa *sa, int srcdst, size_t *sz)
{
  struct ipsec_sa *ipsec = (struct ipsec_sa *) sa->data;
  struct in_addr addr, mask;
  u_int16_t port;
  int id_type = 0;

  switch (srcdst)
    {
	case SRC:
	  port = ipsec->sport;
	  addr.s_addr = ipsec->src_net;
	  mask.s_addr = ipsec->src_mask;
	  break;
	case DST:
	  port = ipsec->dport;
	  addr.s_addr = ipsec->dst_net;
	  mask.s_addr = ipsec->dst_mask;
	  break;
	default:
	  log_print ("gdoi_build_tek_id_from_sa: "
	  			 "Unsupported SRC/DST type (%d)", srcdst);
	  return 0;
	}
  id_type = (mask.s_addr == 0xffffffff) ? IPSEC_ID_IPV4_ADDR :
	  								   	  IPSEC_ID_IPV4_ADDR_SUBNET;
      
  return gdoi_build_tek_id_internal (id_type, addr, mask, port, sz);  
}

/*
 * Out of a named section SECTION in the configuration file store 
 * src/dst identification info in a stored kek for later use.
 */
int
gdoi_store_kek_ids (char *section, struct gdoi_kek *stored_kek)
{
  struct in_addr addr, mask;
  uint16_t port;
  int id_type;
  char *id;
      
  id = conf_get_str (section, "Src-ID");
  if (!id) 
  	{
   	  log_print ("gdoi_store_kek_ids: Src-ID missing");
  	  return -1;
   	}
  if (gdoi_get_id (id, &id_type, &addr, &mask, &port))
    {
      return -1;
    }
  switch (id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
  	  stored_kek->src_addr = addr.s_addr;
  	  stored_kek->sport = port;
	  break;
  	default:
      log_print ("gdoi_store_kek_ids: "
                 "Unsupported ID type (%d) for KEK src", id_type);
	  return -1;
	}
  
  id = conf_get_str (section, "Dst-ID");
  if (!id)
	{
 	  log_print ("gdoi_store_kek_ids: Dst-ID missing");
	  return -1;
	}
  if (gdoi_get_id (id, &id_type, &addr, &mask, &port))
    {
      return -1;
    }
  switch (id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
  	  stored_kek->dst_addr = addr.s_addr;
  	  stored_kek->dport = port;
	  break;
  	default:
      log_print ("gdoi_store_kek_ids: "
                 "Unsupported ID type (%d) for KEK dst", id_type);
	  return -1;
	}

  return 0;
}

/*
 * Out of a KEK structure build the identity fields for a KEK payload.
 * The payload size should be stashed in SZ. The caller is responsible for 
 * freeing the payload.
 */
u_int8_t *
gdoi_build_kek_id (int srcdst, size_t *sz, struct gdoi_kek *stored_kek)
{
  struct in_addr addr, mask;
  uint16_t port;
  u_int8_t *p;
  int id_type;
  size_t id_payload_len;

  switch (srcdst) 
    {
	case SRC:
	  addr.s_addr = stored_kek->src_addr;
	  port = stored_kek->sport;
	  break;
	case DST:
	  addr.s_addr = stored_kek->dst_addr;
	  port = stored_kek->dport;
	  break;
    default:
      log_print ("gdoi_build_kek_id: "
                 "Unsupported SRC/DST type (%d)", srcdst);
      return 0;
	}
  id_type = IPSEC_ID_IPV4_ADDR; /* Only IPv4 for now */
  
  /*
   * Initialize size to the size of the structure except for the 
   * identity data.
   */
  *sz = GDOI_SA_ID_DATA_LEN_OFF + GDOI_SA_ID_DATA_LEN_LEN;
  switch (id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
	  id_payload_len = sizeof addr;
      break;
    default:
      log_print ("gdoi_build_kek_id: "
                 "Unsupported ID type (%d) for ESP", id_type);
      return 0;
    }
  *sz += id_payload_len;
  p = calloc(1, *sz);
  if (!p)
    {
      log_error ("gdoi_build_kek_id: "
	             "calloc(%d) failed", *sz);
	  return 0;
    }

  /*
   * Fill in the src id structure
   */
  SET_GDOI_SA_ID_TYPE(p, id_type);
  SET_GDOI_SA_ID_PORT(p, port);
  SET_GDOI_SA_ID_DATA_LEN(p, id_payload_len);
  switch (id_type)
    {
    case IPSEC_ID_IPV4_ADDR:
      encode_32 (p + GDOI_SA_ID_DATA_OFF, ntohl (addr.s_addr));
      break;
    case IPSEC_ID_IPV4_ADDR_SUBNET:
      encode_32 (p + GDOI_SA_ID_DATA_OFF, ntohl (addr.s_addr));
      encode_32 (p + GDOI_SA_ID_DATA_OFF + sizeof addr, 
	  			 ntohl (mask.s_addr));
      break;
    default:
      log_print ("gdoi_build_id: "
	         "Unsupported ID type (%d) for ESP", id_type);
      free (p);
      return 0;
	}

  return p;
}

void
gdoi_free_attr_payloads (void)
{
  struct extended_attrs *thisp;
  thisp = TAILQ_FIRST (&attr_payloads);
  while (thisp)
    {
      TAILQ_REMOVE(&attr_payloads, thisp, link);
      free(thisp->attr_payload);
	  free(thisp);
  	  thisp = TAILQ_FIRST (&attr_payloads);
    }
}

/*
 * Add a SPI to the exchange verification SPI list.
 */
int
gdoi_add_spi_to_list (struct exchange *exchange, struct sa *sa)
{
  struct gdoi_exch *ie = exchange->data;
  struct tekspi *tekspi = calloc(1, sizeof (struct tekspi));
  struct proto *proto = TAILQ_FIRST (&sa->protos);

  if (!tekspi)
    {
      log_print ("gdoi_add_ipsec_spi_to_list: calloc failed (tekspi)");
	  return -1;
	}
  tekspi->spi_sz = proto->spi_sz[0];
  tekspi->spi = calloc(1, tekspi->spi_sz);
  if (!tekspi->spi)
    {
      log_print ("gdoi_add_ipsec_spi_to_list: calloc failed (spi)");
	  return -1;
	}
  memcpy(tekspi->spi, proto->spi[0], tekspi->spi_sz);
 
  if (tekspi->spi_sz == 4)
    {
  	  log_print ("gdoi_add_ipsec_spi_to_list: Adding TEK SPI %u (%d) (%#x) to SA",
		  	 	  *(u_int32_t *)tekspi->spi, *(u_int32_t *)tekspi->spi, 
				  *(u_int32_t *)tekspi->spi);
 	}
  else
    {
  	  log_print ("gdoi_add_ipsec_spi_to_list: Adding TEK to SA (SPI unknown)");
	}

  TAILQ_INSERT_TAIL(&ie->spis, tekspi, link);

  return 0;
}

static void
gdoi_remove_spi_from_list (struct gdoi_exch *ie, struct tekspi *tekspi)
{
  TAILQ_REMOVE(&ie->spis, tekspi, link);
  free(tekspi->spi);
  free(tekspi);
  return;
}

static void
gdoi_clear_spi_list (struct exchange *exchange)
{
  struct gdoi_exch *ie = exchange->data;
  struct tekspi *tekspi;

  tekspi = TAILQ_FIRST (&ie->spis);
  while (tekspi)
    {
	  gdoi_remove_spi_from_list(ie, tekspi);
  	  tekspi = TAILQ_FIRST (&ie->spis);
    }
}

/*
 * Find the TEK-specific policy for an IPSEC ESP or AH type TEK.
 * Accoding to the GDOI Update draft, they have the same packet format, and 
 * this is assumed in this function.
 *
 * This function doesn't really know whether the policy is ESP or AH until it
 * is read from the configuration file.
 */
static int 
gdoi_ipsec_set_policy (char *conf_field, struct message *msg,
					   struct exchange *sa_exchange)
{
  struct sa *sa;
  char *tek_suite_conf, *life_conf;
  char *protocol_id, *transform_id;
  char *src_id, *dst_id;
  u_int8_t transform_value;
  struct proto *proto;
  struct ipsec_proto *iproto;
  struct ipsec_sa *ipsec;
  struct gdoi_kd_decode_arg keys;
  char *name;
  int value;
  int i;
  int id;
  struct in_addr addr;
  struct in_addr mask;
  uint16_t port;

  /*
   * Find the sa. The last SA in the list was just created for our use.
   */
  sa = TAILQ_LAST (&sa_exchange->sa_list, sa_head);
  if (!sa)
   	{
   	  log_error ("gdoi_ipsec_set_policy: No sa's in list!");
   	  goto bail_out;
	}

  /*
   * Assume ESP for now, and correct it if necessary after reading the
   * configuration.
   */
  if (gdoi_setup_sa (sa, &proto, IPSEC_PROTO_IPSEC_ESP,
					 sizeof(struct ipsec_proto)))
	{
  	  goto bail_out;
  	}
  iproto = (struct ipsec_proto *) proto->data;
  ipsec = (struct ipsec_sa *) sa->data;

  ipsec->tproto = 0; /* Any IP protocol is allowed between Src and Dst */
  /*
   * Get the src/dst IDs.
   */
  src_id = conf_get_str (conf_field, "Src-ID");
  if (!src_id) 
    {
      log_print ("gdoi_ipsec_set_policy: Src-ID missing");
  	  goto bail_out;
    }
  if (gdoi_get_id (src_id, &id, &addr, &mask, &port))
  	{
   	  goto bail_out;
   	}
  ipsec->src_net = htonl(addr.s_addr);
  ipsec->src_mask = htonl(mask.s_addr);
  ipsec->sport = ntohs(port);

  dst_id = conf_get_str (conf_field, "Dst-ID");
  if (!dst_id)
    {
      log_print ("gdoi_ipsec_set_policy: Dst-ID missing");
  	  goto bail_out;
    }
  if (gdoi_get_id (dst_id, &id, &addr, &mask, &port))
  	{
   	  goto bail_out;
   	}
  ipsec->dst_net = htonl(addr.s_addr);
  ipsec->dst_mask = htonl(mask.s_addr);
  ipsec->dport = ntohs(port);

  /*
   * Get a suite defined for this group.
   */
  tek_suite_conf = conf_get_str (conf_field, "TEK_Suite");
  if (!tek_suite_conf)
    {
  	  goto bail_out;
    }
  /*
   * Get the individual protocol configuration
   *
   * Only IPSec ESP and AH is supported for now (not compression).
   */
  protocol_id = conf_get_str (tek_suite_conf, "PROTOCOL_ID");
  if (!protocol_id)
    {
      goto bail_out;
    }
  proto->proto = constant_value(ipsec_proto_cst, protocol_id);

  /*
   * Need to put the Transform ID in the ESP TEK header since it's not
   * treated as an attribute. 
   */
  transform_id = conf_get_str (tek_suite_conf, "TRANSFORM_ID");
  if (!transform_id)
    {
      goto bail_out;
    }
  /*
   * Transform values depend on whether this is ESP or AH.
   */
  switch (proto->proto)
    {
	  case IPSEC_PROTO_IPSEC_ESP:
      	transform_value = constant_value(ipsec_esp_cst, transform_id);
		break;
	  case IPSEC_PROTO_IPSEC_AH:
      	transform_value = constant_value(ipsec_ah_cst, transform_id);
		break;
	  default:
		transform_value = 0;
		break;
	}
  if (!transform_value)
    {
      goto bail_out;
    }
  proto->id = transform_value;

  /*
   * Generate the secrecy keys and stuff in a structure. We'll save them in
   * the sa proto field later so that we can push them in a KD payload
   * later.
   */

  memset((void *)&keys, 0, sizeof(struct gdoi_kd_decode_arg));
  switch (proto->proto)
    {
	case IPSEC_PROTO_IPSEC_ESP:
	  switch (transform_value) 
	    {
		case IPSEC_ESP_AES_GCM_16:
		  keys.sec_key_sz = AES128_LENGTH + GCM_SALT_LENGTH;
		  keys.sec_key = calloc(1, keys.sec_key_sz);
		  if (!keys.sec_key)
      	  	{
         	  log_print ("gdoi_ipsec_set_policy: "
       		   	   	   	 "calloc failed (%d)", keys.sec_key_sz);
         	  goto bail_out;
  			}
	 	  getrandom(keys.sec_key, keys.sec_key_sz);
	  	  LOG_DBG_BUF ((LOG_MISC, 90, "gdoi_ipsec_set_policy: "
						"Generated AES key", keys.sec_key, keys.sec_key_sz));
		  break;
		case IPSEC_ESP_AES_CBC:
		  keys.sec_key_sz = AES128_LENGTH;
		  keys.sec_key = calloc(1, keys.sec_key_sz);
		  if (!keys.sec_key)
      	  	{
         	  log_print ("gdoi_ipsec_set_policy: "
       		   	   	   	 "calloc failed (%d)", keys.sec_key_sz);
         	  goto bail_out;
  			}
		  getrandom(keys.sec_key, keys.sec_key_sz);
	  	  LOG_DBG_BUF ((LOG_MISC, 90, "gdoi_ipsec_set_policy: "
					   "Generated AES key", keys.sec_key, keys.sec_key_sz));
		  break;
		case IPSEC_ESP_3DES:
		  keys.sec_key_sz = 3 * DES_LENGTH;
		  keys.sec_key = calloc(1, keys.sec_key_sz);
		  if (!keys.sec_key)
      		{
         	  log_print ("gdoi_ipsec_set_policy: "
       		   	   	   	 "calloc failed (%d)", keys.sec_key_sz);
         	  goto bail_out;
  			}
		  for (i=0; i<3; i++)
		    {
		  	  getrandom((keys.sec_key + (i*DES_LENGTH)), DES_LENGTH);
			}
	  	  LOG_DBG_BUF ((LOG_MISC, 90, "gdoi_ipsec_set_policy: "
						 "Generated 3DES key", keys.sec_key, keys.sec_key_sz));
		  break;
	 	default:
       	  log_print ("gdoi_ipsec_set_policy: invalid ESP transform_value (%d)", 
					 transform_value);
       	  goto bail_out;
	     }
	  /*
       * If there is an authentication algorithm, store it as an 
	   * attribute and go back to find the key in the configuration 
	   * following the TEK_Suite.
       */
  	  name = conf_get_str (tek_suite_conf, "AUTHENTICATION_ALGORITHM");
  	  if (name) 
        {
		  /*
		   * First check to make sure it's legit to have an
		   * authentication algorithm. For a combined mode such as GCM 
		   * it is NOT legit.
		   */
		  if (gdoi_ipsec_is_counter_mode_tek(proto->proto, transform_value))
		  	{
		  	  log_print ("gdoi_ipsec_set_policy: Authentication "
				         "algorithm not valid with protocol %d "
					     "transform %d", proto->proto, transform_value);
			  goto bail_out;
		  	}
  	  	  value = constant_value (ipsec_auth_cst, name);
  		  switch(value)
      	  	{
    	  	case IPSEC_AUTH_HMAC_SHA:
	  	  	  iproto->auth = IPSEC_AUTH_HMAC_SHA;
	  	  	  break;
    	  	case IPSEC_AUTH_HMAC_SHA2_256:
	  	  	  iproto->auth = IPSEC_AUTH_HMAC_SHA2_256;
	  	  	  break;
   	  	    case IPSEC_AUTH_HMAC_MD5:
	      	  iproto->auth = IPSEC_AUTH_HMAC_MD5;
	  	  	  break;
  		    default:
	  	 	  log_print ("gdoi_ipsec_set_policy: "
           	        	 "Unknown auth key type found (%d).", value);
              goto bail_out;
      	    }
  		  keys.int_key_sz = ipsec_esp_authkeylength(proto);
  		  keys.int_key = malloc(keys.int_key_sz);
    	  if (!keys.int_key)
          	{
        	  log_print ("gdoi_ipsec_set_policy: malloc failed (%d)", 
					  	 keys.int_key);
         	  goto bail_out;
        	}
	 	  getrandom(keys.int_key, keys.int_key_sz);
  	 	  LOG_DBG_BUF ((LOG_MISC, 90, 
			     	  "gdoi_ipsec_set_policy: Generated auth key", 
				 	  keys.int_key, keys.int_key_sz));
  	    }
	  break;

	case IPSEC_PROTO_IPSEC_AH:
	  switch (transform_value) 
	    {
		  case IPSEC_AH_SHA:
			keys.int_key_sz = HMAC_SHA_LENGTH;
			keys.int_key = calloc(1, keys.int_key_sz);
			if (!keys.int_key)
      		  {
         		log_print ("gdoi_ipsec_set_policy: "
       		   	   	   	   "calloc failed (%d)", keys.int_key_sz);
         		goto bail_out;
  			  }
		  	getrandom(keys.int_key, HMAC_SHA_LENGTH);
	  		LOG_DBG_BUF ((LOG_MISC, 90, 
					     "gdoi_ipsec_set_policy: "
						 "Generated SHA-HMAC key", 
						  keys.sec_key, keys.sec_key_sz));
			break;
		  case IPSEC_AH_SHA2_256:
			keys.int_key_sz = HMAC_SHA256_LENGTH;
			keys.int_key = calloc(1, keys.int_key_sz);
			if (!keys.int_key)
      		  {
         		log_print ("gdoi_ipsec_set_policy: "
       		   	   	   	   "calloc failed (%d)", keys.int_key_sz);
         		goto bail_out;
  			  }
		  	getrandom(keys.int_key, HMAC_SHA256_LENGTH);
	  		LOG_DBG_BUF ((LOG_MISC, 90, 
				     	   "gdoi_ipsec_set_policy: "
						   "Generated SHA-HMAC key", 
					 	   keys.sec_key, keys.sec_key_sz));
			break; default:
		  	/* 
			 * HMAC-MD5 not supported
			 */
       	  	log_print ("gdoi_ipsec_set_policy: "
	       		   	   "invalid transform_value (%d)", transform_value);
       	  	goto bail_out;
		}
    }
  /*
   * Stuff the secrecy and integrity keys into the ipsec proto 
   * structure.
   */
  if (stuff_tek_keys(&keys, iproto))
  	{
  	  return -1;
	}
      
  /*
   * Set the SPI for this TEK. Reject SPIs < 255 for simplicity, although
   * only SPIs between 101 and 255 are actually acceptable.
   */
  proto->spi_sz[0] = 4; /* IPsec SPI length */
  proto->spi[0] = malloc(proto->spi_sz[0]);
  if (!proto->spi[0])
    {
	  log_print ("gdoi_ipsec_set_policy: malloc failed (%d)", 
			  	  proto->spi_sz[0]);
	  goto bail_out;
	}
  do {
	getrandom (proto->spi[0], proto->spi_sz[0]);
   } while ((proto->spi[0] != 0x0) && (proto->spi[1] != 0x0) &&
		    (proto->spi[2] != 0x0));

  name = conf_get_str (tek_suite_conf, "ENCAPSULATION_MODE");
  if (name)
	{
	  value = constant_value (ipsec_encap_cst, name);
	  iproto->encap_mode = value;
	}
  
  life_conf = conf_get_str (tek_suite_conf, "Life");
  if (!life_conf)
	{
	  log_print ("gdoi_ipsec_set_policy: TEK has no Life policy");
	  goto bail_out;
	}
  name = conf_get_str (life_conf, "LIFE_TYPE");
  if (!name)
  	{
	  log_print ("gdoi_ipsec_set_policy: TEK must have LIFE_TYPE:");
	  goto bail_out;
	}
  value = conf_get_num (life_conf, "LIFE_DURATION", 0);
  if (value)
  	{
	  sa->seconds = value;
	  sa->start_time = time((time_t)0);
   	}

  /*
   * Check for an Address Preservation directive.
   */
  name = conf_get_str (tek_suite_conf, "ADDRESS_PRESERVATION");
  if (name) 
  	{
  	  value = constant_value (ipsec_addr_pres_cst, name);
	  iproto->addr_pres = value;
	} 

  /*
   * Check for an SA direction directive
   */
   name = conf_get_str (tek_suite_conf, "SA_DIRECTION");
   if (name) 
   	{
  	  value = constant_value (ipsec_sa_direction_cst, name);
	  iproto->sa_direction = value;
	}
   
  return 0;

bail_out:
  return -1;
}

static int gdoi_set_kek_policy (char *conf_field, struct gdoi_kek *stored_kek,
						struct message *msg)
{
  struct exchange *exchange = msg->exchange;
  char *period_str;
  u_int8_t *conf_string;
  int ret;
  u_int8_t *keyfile;

  /*
   * Setup the basics of the exchange.
   */
  getrandom(stored_kek->spi, KEK_SPI_SIZE);
  log_print ("gdoi_set_kek_policy: KEK SPI: %s", 
		 octet_string_hex_string(stored_kek->spi, KEK_SPI_SIZE));
  stored_kek->exchange_name = malloc(strlen(exchange->name));
  if (!stored_kek->exchange_name)
  	{
   	  log_print ("gdoi_set_kek_policy: malloc of exchange name failed (%d)\n",
				 strlen(exchange->name));
	  return -1;
	}
	strcpy(stored_kek->exchange_name, exchange->name);
  if (gdoi_rekey_setup_exchange(stored_kek))
	{
	  return -1;
	}

  /*
   * If the string is NULL, mark that only the exchange is being used,  which
   * means there is no KEK policy in the stored_kek structure.
   */
  if (!conf_field)
	{
	  stored_kek->flags = USE_EXCH_ONLY;
	  return 0;
	}

  /*
   * Newly formed rekey policy. Initialize the rekey exchange sequence
   * number. Also set the period for sending out KEKs.
   */
  stored_kek->current_seq_num = 0;

  /*
   * Deterimine the interval to change the TEK.
   */
  period_str = conf_get_str (conf_field, "REKEY_PERIOD");
 if (period_str) 
    {
	  stored_kek->tek_timer_interval = atoi(period_str); 
	}
  else
   	{
	  stored_kek->tek_timer_interval = DEFAULT_REKEY_PERIOD;
   	  log_print ("gdoi_set_kek_policy: Using default REKEY_PERIOD.");
   	}
  log_print ("gdoi_set_kek_policy: "
			 "Setting a rekey period of %d seconds.", 
			 stored_kek->tek_timer_interval);

  /*
   * Deterimine the interval to change the KEK.
   */
  period_str = conf_get_str (conf_field, "KEK_REKEY_PERIOD");
  if (period_str) 
    {
	  stored_kek->kek_timer_interval = atoi(period_str); 
	}
  else
   	{
	  stored_kek->kek_timer_interval = DEFAULT_KEK_REKEY_PERIOD;
   	  log_print ("gdoi_set_kek_policy: Using default REKEY_PERIOD.");
   	}
  log_print ("gdoi_set_kek_policy: Setting a KEK rekey period of %d seconds.", 
			 stored_kek->kek_timer_interval);

  /*
   * Get the src/dst IDs.
   */
  ret = gdoi_store_kek_ids (conf_field, stored_kek);
  if (ret)
	{
      return -1;
	}

  /*
   * Set the encryption algorithm and initial keys.
   */
  conf_string = (u_int8_t *)conf_get_str (conf_field, "ENCRYPTION_ALGORITHM");
  if (!conf_string)
  	{
   	  log_print ("gdoi_set_kek_policy: ENCRYPTION_ALGORITHM missing");
 	  return -1;
	}
  stored_kek->encrypt_alg = constant_value (gdoi_kek_alg_cst, 
			  									(char *)conf_string);

  /*
   * Generate the encryption keys
   */
  switch(stored_kek->encrypt_alg) 
    {
    case GDOI_KEK_ALG_3DES:
	  /*
	   * This is 3DES-CBC. CBC  requires both an IV and algorithm sent.
	   * Read the IV first
	   */
	  stored_kek->encrypt_iv = calloc(1, DES_LENGTH);
	  if (!stored_kek->encrypt_iv)
		{
      	  log_error ("gdoi_set_kek_policy: calloc failed (%d)", DES_LENGTH);
	  	  return -1;
		}
	  getrandom(stored_kek->encrypt_iv, DES_LENGTH);
	  /*
	   * Now get the keys.
	   */
	  stored_kek->encrypt_key = calloc(1, 3 * DES_LENGTH);
	  if (!stored_kek->encrypt_key)
		{
      	  log_error ("gdoi_set_kek_policy: calloc failed (%d)", 3 * DES_LENGTH);
	  	  return -1;
		}
	  /*
	   * Generate the keys together. 
	   */
	  getrandom(stored_kek->encrypt_key, 3 * DES_LENGTH);
	  break;

	case GDOI_KEK_ALG_AES:
	  /*
	   * Only support 128-bit AES keys for now.
	   *
	   * This is AES-CBC mode. CBC requires both an IV and key sent.
	   * Derive the IV first.
	   */
	  stored_kek->encrypt_iv = calloc(1, AES128_LENGTH);
	  if (!stored_kek->encrypt_iv)
		{
      	  log_error ("gdoi_set_kek_policy: calloc failed (%d)", AES128_LENGTH);
		    return -1;
		}
	  getrandom(stored_kek->encrypt_iv, AES128_LENGTH);
      log_print ("gdoi_set_kek_policy: KEK IV: %s", 
		  octet_string_hex_string(stored_kek->encrypt_iv, AES128_LENGTH));
	  /*
	   * Now set the key.
	   */
	  stored_kek->encrypt_key = calloc(1, AES128_LENGTH);
	  if (!stored_kek->encrypt_key)
	    {
    	  log_error ("gdoi_set_kek_policy: calloc failed (%d)", AES128_LENGTH);
		  return -1;
		}
	  getrandom(stored_kek->encrypt_key, AES128_LENGTH);
      log_print ("gdoi_set_kek_policy: KEK Key: %s", 
		  octet_string_hex_string(stored_kek->encrypt_key, AES128_LENGTH));
	  /*
	   * Store the length of the AES key in bits.
	   */
	  stored_kek->encrypt_key_len = AES128_LENGTH;
	  break;

	case GDOI_KEK_ALG_DES:
	default:
      log_error ("gdoi_set_kek_policy: Unsupported KEK Algorithm type %s",
				 stored_kek->encrypt_alg);
	  return -1;
	  break;

	}

  /*
   * Generate the authentication keys.
   */
  conf_string = (u_int8_t *)conf_get_str (conf_field, "SIG_HASH_ALGORITHM");
  if (!conf_string)
    {
      log_print ("gdoi_set_kek_policy: SIG_HASH_ALGORITHM missing");
 	  return -1;
	}
  stored_kek->sig_hash_alg = 
	 	constant_value (gdoi_kek_hash_alg_cst, (char *)conf_string);
  if (stored_kek->sig_hash_alg == 0)
  	{
   	  log_print ("gdoi_set_kek_policy: SIG_HASH_ALGORITHM type unknown");
 	  return -1;
	}

  /*
   * Get the KEK signature keys.
   */
  conf_string = (u_int8_t *)conf_get_str (conf_field, "SIG_ALGORITHM");
  if (!conf_string)
  	{
   	  log_print ("gdoi_set_kek_policy: SIG_ALGORITHM missing");
 	  return -1;
	}
  stored_kek->sig_alg = constant_value (gdoi_kek_sig_alg_cst, 
		  								(char *)conf_string);
  /*
   * Read the signature keypair and stuff away for later use.
   * We also need to package up the public key to put in the KEK
   * policy attribute.
   */
  switch(stored_kek->sig_alg) 
    {
	case GDOI_KEK_SIG_ALG_RSA:
	  /*
	   * BEW: Should generate the RSA keypair rather than get it out of the 
	   * config.
	   */
	  keyfile = (u_int8_t *)conf_get_str (conf_field, "RSA-Keypair");
      if (!keyfile)
        {
       	  log_error ("gdoi_set_kek_policy: RSA-Keypair not found.");
       	  return -1;
		}
	  if (gdoi_read_keypair (keyfile, stored_kek))
	  	{
       	  log_error ("gdoi_set_kek_policy: Reading RSA-Kepair failed");
		  return -1;
		}
	  break;

	default:
      log_error ("gdoi_set_kek_policy: Unsupported KEK Signature type %s",
					 stored_kek->sig_alg);
	  return -1;
	}

  return 0;
}

static int gdoi_get_gap_policy (char *conf_field, u_int8_t **ret_buf, 
								size_t *ret_buf_sz)
{
  char *str;
  u_int8_t *attr, *attr_start;
  int atd = 0;
  int dtd = 0;
  size_t gap_sz;
  u_int8_t *gap_buf;

  /*
   * Find the ATD and DTD
   */
  str = conf_get_str (conf_field, "ATD");
  if (str) 
    {
	  atd = atoi(str); 
  	  log_print ("gdoi_get_gap_policy: Setting an ATD value of %d seconds.", 
			 	  atd);
	}

  str = conf_get_str (conf_field, "DTD");
  if (str) 
    {
	  dtd = atoi(str); 
  	  log_print ("gdoi_get_gap_policy: Setting a DTD value of %d seconds.", 
			 	  dtd);
	}

  if (!atd && !dtd) {
	  log_print ("gdoi_get_gap_policy: GAP policy decleard but none found!\n");
	  return -1;
  }

  /*
   * Create the GAP header payload
   */
  gap_sz = GDOI_GEN_LENGTH_OFF + GDOI_GEN_LENGTH_LEN;
  gap_buf = calloc(1, gap_sz);
  if (!gap_buf)
    {
      log_print ("gdoi_get_kek_policy: calloc failed (gap_buf)");
	  return -1;
    }

  /*
   * Setup the generic header except for the length & next payload.
   */
  SET_GDOI_GEN_RESERVED(gap_buf, 0);
  

  /*
   * Allocate a block for building attributes. It's sized large enough
   * so that we think it will avoid buffer overflows....
   */
  attr_start = attr = calloc(1, ATTR_SIZE); 
  if (!attr)
    {
      log_print ("gdoi_get_kek_policy: calloc(%d) failed", ATTR_SIZE);
      free(gap_buf);
	  return -1;
	}

  /*
   * Send the ACTIVATION_TIME_DELAY (optional)
   */
  if (atd)
	{
  	  attr = attribute_set_basic (attr, GDOI_GAP_ACTIVATION_TIME_DELAY, atd);
	}

  /*
   * Send the DEACTIVATION_TIME_DELAY (optional)
   */
  if (dtd)
	{
  	  attr = attribute_set_basic (attr, GDOI_GAP_DEACTIVATION_TIME_DELAY, dtd);
	}

  /*
   * Done adding attributes!
   */
  gap_buf = gdoi_grow_buf(gap_buf, &gap_sz, attr_start, 
						(attr - attr_start));
  free(attr_start);
  if (!gap_buf) 
    {
		return -1;
  	}
   
SET_GDOI_GEN_LENGTH(gap_buf, gap_sz);

*ret_buf = gap_buf;
*ret_buf_sz = gap_sz;

return 0;

}
static int gdoi_get_kek_policy (char *conf_field, u_int8_t **ret_buf, 
						   size_t *ret_buf_sz, struct gdoi_kek *stored_kek)
{
  size_t sz;
  u_int8_t *attr, *attr_start;
  u_int8_t *buf, *kek_buf = 0;
  size_t kek_buf_sz;
  int key_size_in_bits;

  /*
   * Create the KEK header payload
   */
  sz = GDOI_GEN_LENGTH_OFF + GDOI_GEN_LENGTH_LEN;
  buf = calloc(1, sz);
  if (!buf)
    {
      log_print ("gdoi_get_kek_policy: calloc failed (buf)");
	  goto bail_out;
    }

  /*
   * Setup the generic header except for the length & next payload.
   */
  SET_GDOI_GEN_RESERVED(buf, 0);
  
  kek_buf = buf;
  kek_buf_sz = sz;

  /*
   * Set the protocol
   */
  sz = GDOI_SA_KEK_PROTOCOL_OFF + GDOI_SA_KEK_PROTOCOL_LEN;
  buf = calloc(1, sz);
  if (!buf)
	{
	  log_print ("gdoi_get_kek_policy: calloc failed (kek_p)");
	  goto bail_out;
    }
  SET_GDOI_SA_KEK_PROTOCOL(buf, IPPROTO_UDP); /* UDP */
  kek_buf = gdoi_grow_buf(kek_buf, &kek_buf_sz, buf, sz);

  /*
   * Set the IDs
   */
  buf = gdoi_build_kek_id (SRC, &sz, stored_kek);
  kek_buf = gdoi_grow_buf(kek_buf, &kek_buf_sz, buf, sz);
  free(buf);
  buf = NULL;
  buf = gdoi_build_kek_id (DST, &sz, stored_kek);
  kek_buf = gdoi_grow_buf(kek_buf, &kek_buf_sz, buf, sz);
  free(buf);
  buf = NULL;
  
  /*
   * Get the "SPI" (ISAKMP HDR cookie pair)
   */
  sz = GDOI_SA_KEK_END_POP_KEYLEN_OFF + GDOI_SA_KEK_END_POP_KEYLEN_LEN;
  buf = calloc(1, sz);
  if (!buf)
	{
	  log_print ("gdoi_get_kek_policy: calloc failed (buf)");
	  goto bail_out;
    }
  if (stored_kek->flags & SEND_NEW_KEK)
	{
  	  if (stored_kek->flags & CREATE_NEW_KEK)
	    {
	  	  /*
	   	   * Create a new SPI 
	   	   */
	  	  getrandom(stored_kek->next_kek_policy.spi, KEK_SPI_SIZE);
	    }
	  /*
	   * Send the new SPI rather than the old one.
	   */
  	  SET_GDOI_SA_KEK_END_SPI(buf, stored_kek->next_kek_policy.spi);
	}
  else
  {
  	SET_GDOI_SA_KEK_END_SPI(buf, stored_kek->spi);
  }
  kek_buf = gdoi_grow_buf(kek_buf, &kek_buf_sz, buf, sz);

  /*
   * Allocate a block for building attributes. It's sized large enough
   * so that we think it will avoid buffer overflows....
   */
  attr_start = attr = calloc(1, ATTR_SIZE); 
  if (!attr)
    {
      log_print ("gdoi_get_kek_policy: calloc(%d) failed", ATTR_SIZE);
      goto bail_out;
	}

  /*
   * Send the KEK_ALGORITHM (required)
   */
 attr = attribute_set_basic (attr, GDOI_ATTR_KEK_ALGORITHM, 
  							 stored_kek->encrypt_alg);

 /*
  * Send the KEK_KEY_LENGTH if KEK_ALGORITHM has a variable length key (e.g.,
  * AES).
  */
  key_size_in_bits = 0;
  switch(stored_kek->encrypt_alg) 
    {
	  case GDOI_KEK_ALG_3DES:
	  case GDOI_KEK_ALG_DES:
		  /*
		   * Don't need to send a length -- it is clear from the length of the
		   * cipher.
		   */
		  break;
	  case GDOI_KEK_ALG_AES:
		  /*
		   * Need to send the size in bits, so convert from bytes.
		   */
  		  attr = attribute_set_basic (attr, GDOI_ATTR_KEK_KEY_LENGTH, 
  							  stored_kek->encrypt_key_len * 8);
		break;
	  default:
        log_error ("gdoi_get_kek_policy: "
		             "Unsupported KEK Algorithm type (KEK_KEY_LENGTH) %s",
					 stored_kek->encrypt_alg);
		goto bail_out;
	}

  /*
   * Send the KEK_KEY_LIFETIME (required)
   */
  attr = attribute_set_basic (attr, GDOI_ATTR_KEK_KEY_LIFETIME, 
  							  stored_kek->kek_timer_interval);

  /*
   * Send the SIG_HASH_ALGORITHM (required)
   */
  attr = attribute_set_basic (attr, GDOI_ATTR_SIG_HASH_ALGORITHM, 
  							  stored_kek->sig_hash_alg);

  /*
   * Send the SIG_ALGORITHM (required)
   */
  attr = attribute_set_basic (attr, GDOI_ATTR_SIG_ALGORITHM, 
  							  stored_kek->sig_alg);
 
  /*
   * Send the SIG_KEY_LENGTH (required)
   */
  if (!stored_kek->signature_key_modulus_size)
	{
      log_print ("gdoi_get_kek_policy: No signature key modulus size!");
	  goto bail_out;
	}
  attr = attribute_set_basic (attr, GDOI_ATTR_SIG_KEY_LENGTH, 
  							  stored_kek->signature_key_modulus_size);

  /*
   * Done adding attributes!
   */

  kek_buf = gdoi_grow_buf(kek_buf, &kek_buf_sz, attr_start, 
  						  (attr - attr_start));
  if (!kek_buf) {
  	  goto bail_out;
	}
  free(attr_start);
	 
  SET_GDOI_GEN_LENGTH(kek_buf, kek_buf_sz);

  *ret_buf = kek_buf;
  *ret_buf_sz = kek_buf_sz;
  return 0;

bail_out:
  free (buf);
  gdoi_free_attr_payloads();
  return -1;
}

int
gdoi_ipsec_get_policy_from_sa (struct sa *sa, u_int8_t **ret_buf,
                           	   size_t *ret_buf_sz)
{
  struct proto *proto;
  struct ipsec_proto *iproto;
  u_int8_t *esp_tek_buf = 0;
  u_int8_t *buf = 0;
  size_t sz, esp_tek_sz;
  u_int8_t *attr, *attr_start = 0;
  int time_left;
  struct gdoi_kd_decode_arg keys;

  proto = TAILQ_FIRST (&sa->protos);
  iproto = (struct ipsec_proto *) proto->data;

  /*
   * Set the protocol
   */
  sz = GDOI_SA_TEK_ESP_SZ;
  buf = calloc(1, sz);
  if (!buf)
  	{
      log_print ("gdoi_ipsec_get_policy_from_sa: calloc failed");
  	  goto bail_out;
    } 
  /* 
   * Hard code the network protocol type to be ignored for now 
   */
  SET_GDOI_SA_TEK_PROT_ID(buf, 0); 
  esp_tek_buf = buf;
  esp_tek_sz = sz;

  /*
   * Get the src/dst IDs.
   */
  buf = gdoi_build_tek_id_from_sa (sa, SRC, &sz);
  if (!buf)
    {
      goto bail_out;
    }
  esp_tek_buf = gdoi_grow_buf(esp_tek_buf, &esp_tek_sz, buf, sz);
  free(buf);
  buf = NULL;

  buf = gdoi_build_tek_id_from_sa (sa, DST, &sz);
  if (!buf)
    {
      goto bail_out;
    }
  esp_tek_buf = gdoi_grow_buf(esp_tek_buf, &esp_tek_sz, buf, sz);
  if (!esp_tek_buf)
    {
      goto bail_out;
	}
  free(buf);
  buf = NULL;

  /*
   * Need to put the Transform ID in the ESP TEK header since it's not
   * treated as an attribute. 
   */
  esp_tek_buf = gdoi_grow_buf(esp_tek_buf, &esp_tek_sz, &proto->id, 
                              sizeof(u_int8_t));
  if (!esp_tek_buf)
    {
      goto bail_out;
	}

  /*
   * Get the SPI for this TEK. 
   */
  esp_tek_buf = gdoi_grow_buf(esp_tek_buf, &esp_tek_sz, 
 						  	  proto->spi[0], proto->spi_sz[0]);
  if (!esp_tek_buf)
    {
      goto bail_out;
	}

  /*
   * Allocate a block for building attributes. It's sized large enough
   * so that we think it will avoid buffer overflows....
   */
  attr_start = attr = calloc(1, ATTR_SIZE); 
  if (!attr)
    {
      log_print ("gdoi_ipsec_get_policy: "
          		 "calloc(%d) failed", ATTR_SIZE);
      goto bail_out;
	}

  attr = attribute_set_basic (attr, IPSEC_ATTR_ENCAPSULATION_MODE, 
							  iproto->encap_mode);

  /*
   * If there is an ESP authentication algorithm, store it as an attribute and
   * go back to find the key in the configuration following the TEK_Suite.
   */
  if ((proto->proto == IPSEC_PROTO_IPSEC_ESP) && iproto->auth)
  	{
  	  attr = attribute_set_basic (attr,
	  							  IPSEC_ATTR_AUTHENTICATION_ALGORITHM, 
								  iproto->auth);
	}
      
  /*
   * Send whatever lifetime info we have, after adjusting from the
   * start time.
   */
  if (sa->seconds)
  	{
	  time_left = sa->seconds  - (time((time_t)0) - sa->start_time);
	  if (time_left > 0)
	    {

  	  	  attr = attribute_set_basic (attr,
	  							  	  IPSEC_ATTR_SA_LIFE_TYPE, 
									  IPSEC_DURATION_SECONDS);
  	  	  attr = attribute_set_basic (attr,
	  							  IPSEC_ATTR_SA_LIFE_DURATION, 
								  time_left);
		}
	  else
	  	{
	  	  log_print ("gdoi_ipsec_get_policy_from_sa: "
		  			 "SA time has expired, but still on SA list!");
		  time_left = 0;
		}
	}

  /*
   * If the ESP transform is AES, we need to send the key size.
   */
  if ((proto->id == IPSEC_ESP_AES_CBC) || (proto->id == IPSEC_ESP_AES_GCM_16))
	{
	  memset((void *)&keys, 0, sizeof(struct gdoi_kd_decode_arg));
  	  if (gdoi_ipsec_get_tek_keys(&keys, proto))
  	  	{
       	  log_print ("gdoi_ipsec_get_policy_from_sa: "
        	   	     "Error in getting AES TEK key length!");
  	  	}
	  /*
	   * Sent in bits, so convert from bytes.
	   */
	  attr = attribute_set_basic (attr, IPSEC_ATTR_KEY_LENGTH,
								  keys.sec_key_sz * 8);
	}

  /*
   * Pass the Address Preservation attribute, if it's not the default.
   */
  if (iproto->addr_pres != IPSEC_ADDR_PRES_SOURCE_AND_DEST) 
	{
  	  attr = attribute_set_basic (attr, IPSEC_ATTR_ADDRESS_PRESERVATION,
			  					  iproto->addr_pres);
	}

  /*
   * Pass the SA Direction attribute, if it's not the default.
   */
  if (iproto->sa_direction != IPSEC_SA_DIRECTION_SYMMETRIC) 
	{
  	  attr = attribute_set_basic (attr, IPSEC_ATTR_SA_DIRECTION,
			  					  iproto->sa_direction);
	}

  /*
   * Add the attributes to the tek payload
   */
  esp_tek_buf = gdoi_grow_buf(esp_tek_buf, &esp_tek_sz, attr_start, 
                               (attr - attr_start));
  free (attr_start);
  if (!esp_tek_buf)
   	{
     goto bail_out;
	}

  *ret_buf = esp_tek_buf;
  *ret_buf_sz = esp_tek_sz;
  return 0;

bail_out:
  free (buf);
  free (attr_start);
  return -1;
}

/*
 * Return whether an SA should be sent to a group member.
 *
 * This depends on the exchange type, and the state of the SA.
 */
int
gdoi_current_sa (u_int8_t type, struct sa *sa)
{
  struct proto *proto;

  /*
   * PUSH SA check
   *
   * For simplicity, for a rekey message only send the SAs 
   * which were just created. Those can be identified as not yet marked 
   * with the SA_FLAG_READY flag.
   */
  if ((type == GDOI_EXCH_PUSH_MODE) && (sa->flags & SA_FLAG_READY))
  	{
	  return FALSE;
	}

  /*
   * PUSH and PULL: Only send live SAs.
   */
  if (sa->flags & SA_FLAG_FADING)
  	{
	  return FALSE;
	}
  proto = TAILQ_FIRST (&sa->protos);
  if (!proto)
  	{
	  return FALSE;
	}

  return TRUE;
}

/*
 * Create a TEK SA payload from an sa structure
 */
u_int8_t *
gdoi_get_current_tek (struct sa *sa, size_t *sz, int last_tek)
{
  struct proto *proto;
  u_int8_t *buf = 0, *tek_p = 0;
  size_t tek_sz; 

  /*
   * 1. Create the generic TEK structure
   * 2. Add the protocol-specific TEK structure (e.g., ESP)
   */
  tek_p = calloc(1, GDOI_SA_TEK_SZ);
  if (!tek_p)
    {
	  log_print ("gdoi_get_current_tek: calloc failed (tek_p)");
  	  goto bail_out;
     }
  
  /*
   * Fill in the TEK structure, except for the length -- it will be
   * filled in after the protocol-specific structure has been created.
   */
  if (last_tek)
    {
  	  SET_GDOI_GEN_NEXT_PAYLOAD(tek_p, 0);
    }
  else
    {
  	  SET_GDOI_GEN_NEXT_PAYLOAD(tek_p, ISAKMP_PAYLOAD_SA_TEK);
    }
  SET_GDOI_GEN_RESERVED(tek_p, 0);
  
  /*
   * Determine what kind of TEK this is & format it.
   */
  proto = TAILQ_FIRST (&sa->protos);
  switch (proto->proto)
    {
	case IPSEC_PROTO_IPSEC_ESP:
	case IPSEC_PROTO_IPSEC_AH:
	  if (proto->proto == IPSEC_PROTO_IPSEC_ESP)
	  	{
  	  	    SET_GDOI_SA_TEK_PROT_ID(tek_p, GDOI_TEK_PROT_PROTO_IPSEC_ESP);
		}
	  else
	    {
  	  	    SET_GDOI_SA_TEK_PROT_ID(tek_p, GDOI_TEK_PROT_PROTO_IPSEC_AH);
		}
	  if (gdoi_ipsec_get_policy_from_sa(sa, &buf, &tek_sz))
		{
          log_error ("gdoi_get_current_tek: "
		             "Getting IPSEC TEK policy failed");
		  goto bail_out;
		}
	  break;
#ifdef SRTP_SUPPORT
	case IPSEC_PROTO_SRTP:
  	  SET_GDOI_SA_TEK_PROT_ID(tek_p, GDOI_TEK_PROT_PROTO_SRTP);
	  if (gdoi_srtp_get_policy_from_sa(sa, &buf, &tek_sz))
		{
          log_error ("gdoi_get_current_tek: "
		             "Getting IPSEC TEK policy failed");
		  goto bail_out;
		}
	  break;
#endif
#ifdef IEC90_5_SUPPORT
	case IPSEC_PROTO_IEC90_5:
  	  SET_GDOI_SA_TEK_PROT_ID(tek_p, GDOI_TEK_PROT_PROTO_IEC90_5);
	  if (gdoi_iec90_5_get_policy_from_sa(sa, &buf, &tek_sz))
		{
          log_error ("gdoi_get_current_tek: "
		             "Getting IPSEC TEK policy failed");
		  goto bail_out;
		}
	  break;
#endif
    default:
      log_print ("gdoi_get_current_tek: Unsupported protocol %d",
	  			 proto->proto);
	  goto bail_out;
	  }

  *sz = GDOI_SA_TEK_SZ + tek_sz;
  SET_GDOI_GEN_LENGTH(tek_p, *sz);
  tek_p = realloc(tek_p, *sz);
  if (!tek_p)
  	{
      log_error ("gdoi_get_current_tek: "
	             "realloc failed");
	  goto bail_out;
	}
  memcpy((tek_p + GDOI_SA_TEK_SZ), buf, tek_sz);
  free(buf);

  return tek_p;

bail_out:
  free (tek_p);
  free (buf);
  return 0;
}

int gdoi_add_sa_payload (struct message *msg)
{
  struct exchange *exchange = msg->exchange;
  struct exchange *sa_exchange;
  struct sa *sa;
  u_int8_t *sa_buf = 0;
  u_int8_t *tek_p = 0;
  u_int8_t *buf = 0;
  size_t sa_len;
  size_t sz;
  struct gdoi_exch *ie = exchange->data;
  struct conf_list *suite_conf;
  struct conf_list_node *suite;
  struct gdoi_kek *stored_kek = NULL;
  char *name, *str;
  char  *tek_type_conf;
  int suite_no, tek_no;
  struct extended_attrs *attrp;
  size_t offset;
  int proto;
  int next_payload = ISAKMP_PAYLOAD_NONE;

  /*
   * Before completing the SA payload, need to get the KEK, GAP, TEK and SA 
   * attributes. We create a list of structures which will be added to the 
   * SA payload, one per TEK or KEK.
   */
  
  /*
   * Initialize the list.
   */
  TAILQ_INIT (&attr_payloads);

  /*
   * Find the group id in the configuration, which identifies the policy for 
   * the group. If we are a rekey message, we might be re-using the exchange
   * and the name is already set.
   */
  if (exchange->name)
	{
	  name = exchange->name;
	}
  else
    {
  	  name = connection_passive_lookup_by_group_id (ie->id_gdoi);
  	  if (name) 
	    {
      	  exchange->name = strdup (name);
      	  if (!exchange->name) 
      	  	{
          	  log_error ("gdoi_add_sa_payload: strdup (\"%s\") failed", 
	          		 	  name);
		  	  goto bail_out;
      		}
    	}
  	  else
    	{
      	  log_error ("gdoi_add_sa_payload: "
	  			 	 "Passive connection not found for group in ID payload.");
	  	  goto bail_out;
		}
	}

  /*
   * Find the Configuration keyword
   */
  if (!exchange->policy)
  	{
  	  exchange->policy = conf_get_str (name, "Configuration");
  	  if (!exchange->policy)
    	{
      	  log_print ("gdoi_add_sa_payload: no configuration for "
                 	 "peer \"%s\"", name);
      	  return -1;
    	}
	}
  
  /* Validate the DOI.  */
  str = conf_get_str (exchange->policy, "DOI");
  if (str)
    {
      if (!(strcasecmp (str, "GROUP") == 0))
	{
	  log_print ("gdoi_add_sa_payload: DOI \"%s\" unsupported " 
	  	     "for group policy", str);
	  return -1;
	}
    }
  else
    {
      log_print ("gdoi_add_sa_payload: DOI missing");
      return -1;
    }

  /* Validate the exchange */
  str = conf_get_str (exchange->policy, "EXCHANGE_TYPE");
  if (str)
    {
      if (!(strcasecmp (str, "PULL_MODE") == 0))
        {
	  	  log_print ("gdoi_add_sa_payload: EXCHANGE_TYPE \"%s\" "
	             	  "unsupported  for group policy", str);
		  return -1;
		}
    }
  else
    {
      log_print ("gdoi_add_sa_payload: EXCHANGE_TYPE missing");
      return -1;
    }

  /*
   * GDOI constraint:
   * Either a KEK or a TEK must be found in the configuration. The only
   * obvious error is if neither is found.
   *
   * Local policy:
   * Registration messages get all of the current TEKs, but no new ones.
   * For each rekey message generate new TEKs to replace those in the
   * configuration. 
   *
   * BEW: This is really broken local policy.
   */
 
  /*
   * Find or create the KEK policy structure. Note: Even if there isn't a KEK
   * (and thus we're not sending rekeys), we're stroring the TEKs in its 
   * exchange to take advantage of the normal SA expiration, etc. semantics.
   */
  str = conf_get_str (exchange->policy, "SA-KEK");
  stored_kek = gdoi_get_kek(ie->id_gdoi, ie->id_gdoi_sz, 0);
  if (!stored_kek)
    {
	  stored_kek = gdoi_get_kek(ie->id_gdoi, ie->id_gdoi_sz, 1);
	  if (!stored_kek)
	  	{
		  goto bail_out;
		}

	  /* 
	   * Initialize the KEK policy, either with the KEK policy if found,
	   * or for use of the echange only.
	   */
	  gdoi_set_kek_policy(str, stored_kek, msg); 
    }

  /*
   * If an SA-KEK was found, create the SA_KEK payload.
   */
  if (str)
   	{
  	  if (gdoi_get_kek_policy(str, &buf, &sz, stored_kek))
		{
   		  log_print ("gdoi_add_sa_payload: Error in getting KEK policy");
		  goto bail_out;
		}
   	  attrp = calloc(1, sizeof (struct extended_attrs));
   	  attrp->attr_payload = buf;
	  attrp->has_generic_header = TRUE;
	  attrp->attr_type = ISAKMP_PAYLOAD_SA_KEK;
   	  attrp->sz = sz;
   	  TAILQ_INSERT_TAIL (&attr_payloads, attrp, link);
    }
  else
    {
      	log_print ("gdoi_add_sa_payload: "
                   "No SA-KEK found -- no rekey will happen");
	}

  /*
   * Generate GAP, if there is any GAP configuration.
   */
  str = conf_get_str (exchange->policy, "GROUP-POLICY");
  if (str)
    {
      if (gdoi_get_gap_policy(str, &buf, &sz))
		{
      	  log_print ("gdoi_add_sa_payload: Error in getting GAP policy");
		  goto bail_out;
		}
      attrp = calloc(1, sizeof (struct extended_attrs));
      attrp->attr_payload = buf;
	  attrp->has_generic_header = TRUE;
	  attrp->attr_type = ISAKMP_PAYLOAD_GAP;
      attrp->sz = sz;
      TAILQ_INSERT_TAIL (&attr_payloads, attrp, link);
    } 
  else 
    {
      log_print ("gdoi_add_sa_payload: No SA-GAP found for this group");
    }

  /*
   * Decide whether or not to create more TEKs:
   * 1. If it's a rekey, and if this isn't a special rekey sending a new KEK.
   * 2. If it's a registration, and there aren't any TEKs in the list (because
   *    they either all expired, or this is the first registeration).
   *
   * In the rekey message case (GDOI_EXCH_PUSH_MODE), a new SA will be 
   * generated for each one in the configuration. New key values and SPIs 
   * will be chosen for the new SAs, of course. 
   *
   * This path, is also chosen in the case of a registration message
   * (GDOI_EXCH_PULL_MODE) when there are no current SPIs on the SPI list.
   * A lack of SPIs on that list means that either there is no KEK for the 
   * group, or that there is a KEK but this is the first registration attempt
   * for the group.
   */
  sa_exchange = stored_kek->send_exchange;
  if (!sa_exchange) {
	log_print ("gdoi_add_sa_payload: sa_exchange missing! Aborting.");
    goto bail_out;
  }

  if (((exchange->type == GDOI_EXCH_PUSH_MODE) && 
			!(stored_kek->flags & SEND_NEW_KEK)) ||
	  ((exchange->type == GDOI_EXCH_PULL_MODE) && 
	   (!TAILQ_FIRST(&sa_exchange->sa_list))))
	{
	  /* 
	   * TEKs are processed as a list.
	   *
	   * This processing follows the style of Quick Mode protocol suite 
	   * processing at the beginning of 
	   * ike_quick_mode.c:initiator_send_HASH_SA_NONCE().
	   *
	   * Create TEK strcutures as we go, and store them in the list for adding 
	   * to the SA payload later.
	   */
	  
	  /*
	   * Evalute the TEK SA policy in the configuration file. 
	   */
      suite_conf = conf_get_list (exchange->policy, "SA-TEKS");
  	  if (!suite_conf)
    	{
      	    log_print ("gdoi_add_sa_payload: No SA-TEKS found");
			goto bail_out;
    	}

	  for (suite = TAILQ_FIRST (&suite_conf->fields), suite_no = tek_no = 0;
	       suite_no < suite_conf->cnt;
	       suite_no++, suite = TAILQ_NEXT (suite, link))
	    {
	  	  /*
	   	   * Before creating the TEK, create an SA to stuff the policy and keys 
	   	   * read in from the config file. The keys are picked up later by the 
		   * KD payload processing. The SAs will also be sent out again later 
		   * in the rekey message if they are still active.
		   *
		   * sa_create calls sa_reference twice. GDOI only needs it
		   * referenced once, so release it once here.
	   	   */
	  	  sa_create(sa_exchange, NULL);
		  
	 	  /*
		   * Determine what kind of TEK this is. Default is IPsec
		   */
	  	  tek_type_conf = conf_get_str (exchange->policy, "Crypto-protocol");
	  	  if (!tek_type_conf)
	    	{
	      	  log_print ("gdoi_add_sa_payload: "
					  	 "Assuming TEK in configuration is IPsec (ESP or AH)");
			  /*
			   * We don't know if its ESP or AH, so mark as ESP for now.
			   * It will be corrected when we read in the configuration.
			   */
			  proto = GDOI_TEK_PROT_PROTO_IPSEC_ESP;
	    	}
		  else
		    {
		  	  proto = constant_value (gdoi_tek_prot_cst, tek_type_conf);
		  	  switch (proto)
		    	{
				case GDOI_TEK_PROT_PROTO_IPSEC_ESP:
				case GDOI_TEK_PROT_PROTO_IPSEC_AH:
#if SRTP_SUPPORT
				case GDOI_TEK_PROT_PROTO_SRTP:
#endif
#ifdef IEC90_5_SUPPORT
				case GDOI_TEK_PROT_PROTO_IEC90_5:
#endif
				  break;
				default:
	        	  log_print ("gdoi_add_sa_payload: "
				             "Unsupported Protocol type %s", tek_type_conf);
				  goto bail_out;
				}
			}

	      /* 
	       * Get this TEK's particular policy. 
	       */
		  switch (proto)
		   	{
			case GDOI_TEK_PROT_PROTO_IPSEC_ESP:
			case GDOI_TEK_PROT_PROTO_IPSEC_AH:
			  if (gdoi_ipsec_set_policy(suite->field, msg, sa_exchange))
				{
	        	  log_error ("gdoi_add_sa_payload: "
				             "Getting IPsec TEK policy failed");
				  goto bail_out;
				}
			  break;
#if SRTP_SUPPORT
			case GDOI_TEK_PROT_PROTO_SRTP:
			  if (gdoi_srtp_set_policy(suite->field, msg, sa_exchange))
				{
	        	  log_error ("gdoi_add_sa_payload: "
				             "Getting SRTP TEK policy failed");
				  goto bail_out;
				}
			  break;
#endif
#if IEC90_5_SUPPORT
			case GDOI_TEK_PROT_PROTO_IEC90_5:
			  if (gdoi_iec90_5_set_policy(suite->field, msg, sa_exchange,
						  				  ie->id_gdoi, ie->id_gdoi_sz))
				{
	        	  log_error ("gdoi_add_sa_payload: "
				             "Getting IEC90-5 TEK policy failed");
				  goto bail_out;
				}
			  break;
#endif
				default:
	        	  log_print ("gdoi_add_sa_payload: "
				             "Unsupported Protocol type %s", tek_type_conf);
				  goto bail_out;
			}
	    }
	}

  /*
   * Now add all the old & new TEKs to the message.
   */
  if (TAILQ_FIRST(&sa_exchange->sa_list))
	{
      for (sa = TAILQ_FIRST (&sa_exchange->sa_list); sa;
	       sa = TAILQ_NEXT (sa, next))
		{
		  if (gdoi_current_sa(exchange->type, sa))
		    {
			  tek_p = gdoi_get_current_tek(sa, &sz, 
			 	  	      (sa == TAILQ_LAST (&sa_exchange->sa_list, sa_head)));
	     	  attrp = calloc(1, sizeof (struct extended_attrs));
	     	  attrp->attr_payload = tek_p;
		  	  attrp->has_generic_header = TRUE;
	  		  attrp->attr_type = ISAKMP_PAYLOAD_SA_TEK;
			  attrp->sz = sz;
	     	  TAILQ_INSERT_TAIL (&attr_payloads, attrp, link);
			   /*
			    * Add the SPI to the exchange list for use of the KD
				* payload processing.
				*/
	  		  gdoi_add_spi_to_list(exchange, sa);
			}
		}
	}

  /*
   * Setup the SA payload. Calculate the length by including all of the
   * extended attributes along with the static part. We're going to create a
   * contiguous SA paylaod buffer using this length.
   *
   * While we're at it, fix the "next payload" of each attribute.
   */
  offset = sa_len = GDOI_SA_SZ;

  TAILQ_FOREACH_REVERSE(attrp, &attr_payloads, attr_payload_list, link)
    {
      sa_len += attrp->sz;
	  if (attrp->has_generic_header == TRUE)
		{
		  SET_GDOI_GEN_NEXT_PAYLOAD(attrp->attr_payload, next_payload);
		  next_payload = attrp->attr_type;
		}
    }

  sa_buf = calloc (1, sa_len);
  if (!sa_buf)
    {
      log_error ("gdoi_add_sa_payload: calloc (%d) failed", sa_len);
      goto bail_out;
    }
  SET_GDOI_GEN_NEXT_PAYLOAD(sa_buf, 0);
  SET_GDOI_GEN_RESERVED(sa_buf, 0);
  SET_GDOI_SA_DOI (sa_buf, GROUP_DOI_GDOI);
  exchange->doi->setup_situation (sa_buf);
  SET_GDOI_SA_SA_ATTR_NEXT (sa_buf, next_payload);
  SET_GDOI_SA_RES2 (sa_buf, 0);

  /* 
   * Copy in the extended attributes.
   */
  for (attrp = TAILQ_FIRST (&attr_payloads); attrp; 
       attrp = TAILQ_NEXT(attrp, link))
    {
      memcpy ((sa_buf + offset), attrp->attr_payload, attrp->sz);
      offset += attrp->sz;
    }
 
  /*
   * Fill in the SA payload length now that its known.
   */
  SET_GDOI_GEN_LENGTH(sa_buf, sa_len);

  /*
   * Add the SA payload, including it's extended attributes.
   */
  if (message_add_payload (msg, ISAKMP_PAYLOAD_SA, sa_buf, sa_len, 1))
    {
      goto bail_out;
	}
  sa_buf = 0;
  gdoi_free_attr_payloads();
  return 0;

bail_out:
  free (buf);
  free (sa_buf);
  gdoi_free_attr_payloads();
  return -1;
}

static int responder_send_HASH_NONCE_SA (struct message *msg)
{
  struct ipsec_sa *isa = msg->isakmp_sa->data;
  struct hash *hash = hash_get (isa->hash);
  struct exchange *exchange = msg->exchange;
  struct gdoi_exch *ie = exchange->data;

  /*
   * Add HASH payload
   */
  if (!ipsec_add_hash_payload (msg, hash->hashsize)) {
    return -1;
  }
    
  /*
   * Add NONCE payload
   */
  if (exchange_gen_nonce (msg, 16)) {
    return -1;
  }

  /*
   * Add SA payload
   */
  TAILQ_INIT(&ie->spis);
  if (gdoi_add_sa_payload (msg)) {
	return -1;
  }

  /*
   * All payloads present and accounted for. Fill in the hash and we're done.
   */
  if (group_fill_in_hash (msg, INC_I_NONCE, NO_R_NONCE))
    {
      return -1;
    }
    
  return 0;
}

int gm_gap_decode_attribute (u_int16_t type, u_int8_t *value, u_int16_t len,
						   void *arg)
{
  struct gdoi_exch *ie = (struct gdoi_exch *) arg;

  switch (type)
    {
	case GDOI_GAP_SENDER_ID_REQUEST:
	  ie->num_sids = decode_16(value);
	  break;
	default:
      log_print ("gm_gap_decode_attribute: Attribute not valid: %d", type);
	  return -1;
	}

  return 0;
}

static int gdoi_process_GM_GAP_payload (struct message *msg)
{
  struct exchange *exchange = msg->exchange;
  struct gdoi_exch *ie = exchange->data;
  struct payload *gap_p;
  u_int8_t *cur_p = 0;

  gap_p = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_GAP]);
  if (!gap_p)
    {
	  /*
	   * GM GAP payload is optional.
	   */
	  return 0;
	}

  gap_p->flags |= PL_MARK;
  log_print("gdoi_process_GM_GAP_payload: Found a payload!");

  cur_p = gap_p->p + GDOI_GEN_SZ;
  attribute_map (cur_p, (GET_GDOI_GEN_LENGTH(gap_p->p) - GDOI_GEN_SZ), 
  				 gm_gap_decode_attribute, ie);
  return 0;
}

static int responder_recv_HASH (struct message *msg)
{
  struct payload *hashp;
  u_int8_t *hash;
  u_int8_t *pkt = msg->iov[0].iov_base;

  hashp = TAILQ_FIRST (&msg->payload[ISAKMP_PAYLOAD_HASH]);
  hash = hashp->p;
  hashp->flags |= PL_MARK;

  /* The HASH payload should be the first one.  */
  if (hash != pkt + ISAKMP_HDR_SZ)
    {
      /* XXX Is there a better notification type?  */
      message_drop (msg, ISAKMP_NOTIFY_PAYLOAD_MALFORMED, 0, 1, 0);
      return -1;
    }
  
  if (group_check_hash(msg, INC_I_NONCE, INC_R_NONCE))
    return -1;

  /*
   * If a GAP payload is present, process it.
   */
  if (gdoi_process_GM_GAP_payload (msg))
	{
	  return -1;
	}

  return 0;
}

int gdoi_add_kd_payload (struct message *msg)
{
  struct exchange *exchange = msg->exchange;
  struct exchange *sa_exchange = 0;
  struct gdoi_exch *ie = exchange->data;
  u_int8_t *seq_buf = 0;
  u_int8_t *kd_buf = 0;
  size_t sz, kd_pak_sz;
  struct sa *sa;
  struct proto *proto;
  size_t total_kd_pak = 0;
  u_int8_t *kd_pak_buf = 0;
  u_int8_t *attr, *attr_start = 0;
  u_int8_t *tmp_buf = 0;
  int tmp_buf_len = 0;
  struct gdoi_kd_decode_arg keys;
  int foundspi;
  struct tekspi *tekspi;
  u_int8_t *iv_to_send, *key_to_send;
  int have_counter_modes = 0;
  struct gdoi_kek *stored_kek = NULL;
  char *conf_field, *str;

  /*
   * Start with the KD header
   */
  sz = GDOI_KD_RES2_OFF+ GDOI_KD_RES2_LEN;
  kd_buf = calloc (1, sz);
  if (!kd_buf)
    {
      log_error ("gdoi_add_kd_payload: calloc (%d) failed", sz);
      goto bail_out;
    }

  /*
   * Add the KEK policy, if one exists for the group. 
   */
  stored_kek = gdoi_get_kek(ie->id_gdoi, ie->id_gdoi_sz, 0);
  if (stored_kek && !(stored_kek->flags & USE_EXCH_ONLY))
	{
   	  kd_pak_sz = GDOI_KD_PAK_SPI_SIZE_OFF + GDOI_KD_PAK_SPI_SIZE_LEN;
  	  kd_pak_buf = calloc(1, kd_pak_sz);
  	  if (!kd_pak_buf)
		{
   	  	  log_error ("gdoi_add_kd_payload: calloc (%d) failed", 
				 	 kd_pak_sz);
   	  	  goto bail_out;
   		}
  	  SET_GDOI_KD_PAK_KD_TYPE(kd_pak_buf, GDOI_KD_TYPE_KEK); 
  	  SET_GDOI_KD_PAK_SPI_SIZE(kd_pak_buf, KEK_SPI_SIZE);
  	  kd_pak_buf = gdoi_grow_buf(kd_pak_buf, &kd_pak_sz, 
							 	 stored_kek->spi, KEK_SPI_SIZE);

  	  /*
	   * Stuff the encryption keys into an attribute block. This is an
   	   * especially large one due to the size of the signature key.
   	   */
   	  attr_start = attr = calloc(1, ATTR_SIZE * 10);
   	  if (!attr)
       	{
      	  log_error ("gdoi_add_kd_payload: "
        		  	 "calloc(%d) failed", ATTR_SIZE);
       	  goto bail_out;
		}
  	  switch(stored_kek->encrypt_alg) 
    	{
		case GDOI_KEK_ALG_3DES:
		  /*
		   * Send the current keys UNLESS flags includes the SEND_NEW_KEK
		   * flag.
		   */
  		  if (stored_kek->flags & SEND_NEW_KEK)
			{
   			  if (stored_kek->flags & CREATE_NEW_KEK)
    			{
				  stored_kek->next_kek_policy.encrypt_iv = malloc(DES_LENGTH);
				  stored_kek->next_kek_policy.encrypt_key =malloc(3*DES_LENGTH);
				  if (!stored_kek->next_kek_policy.encrypt_iv ||
				      !stored_kek->next_kek_policy.encrypt_key) 
				    {
         	  	      log_error ("gdoi_add_kd_payload: "
       	  		     	   			   "Can't malloc space for key or IV\n");
          	  	  	  goto bail_out;
				    }
				  getrandom(stored_kek->next_kek_policy.encrypt_iv, DES_LENGTH);
				  getrandom(stored_kek->next_kek_policy.encrypt_key,
						  	3*DES_LENGTH);
				}
			  iv_to_send = stored_kek->next_kek_policy.encrypt_iv;
			  key_to_send = stored_kek->next_kek_policy.encrypt_key;
			}
		  else
			{
	  	  	  if (!stored_kek->encrypt_iv || !stored_kek->encrypt_key) 
			    {
         	  	  log_error ("gdoi_add_kd_payload: "
       	  		   	 	     "Missing KEK encryption key or IV\n");
          	  	  goto bail_out;
			  	}
			  iv_to_send = stored_kek->encrypt_iv;
			  key_to_send = stored_kek->encrypt_key;
			}

		  /*
		   * Prepend the IV
		   */
		  tmp_buf_len = 4 * DES_LENGTH;
		  tmp_buf = malloc(tmp_buf_len);
		  if (!tmp_buf)
            {
         	  log_error ("gdoi_add_kd_payload: "
       	  		     	 "malloc failed: %d bytes\n", tmp_buf_len);
          	   goto bail_out;
			}
		  memcpy(tmp_buf, iv_to_send, DES_LENGTH);
		  memcpy((tmp_buf+DES_LENGTH), key_to_send, 3*DES_LENGTH);
	  	  attr = attribute_set_var (attr,
					   				GDOI_ATTR_KD_KEK_SECRECY_KEY,
					   		  		tmp_buf, 
									tmp_buf_len);
		  free(tmp_buf);
		  tmp_buf = 0;
		  tmp_buf_len = 0;
	  	  break;

		case GDOI_KEK_ALG_AES:
		  if (stored_kek->flags & SEND_NEW_KEK)
			{
   			  if (stored_kek->flags & CREATE_NEW_KEK)
    			{
				  stored_kek->next_kek_policy.encrypt_iv =
					  	malloc(stored_kek->encrypt_key_len);
				  stored_kek->next_kek_policy.encrypt_key =
					  	malloc(stored_kek->encrypt_key_len);
				  if (!stored_kek->next_kek_policy.encrypt_iv ||
				      !stored_kek->next_kek_policy.encrypt_key) 
				    {
    	  	  		  log_error ("gdoi_add_kd_payload: "
       	  		     	   		 "Can't malloc space for key or IV\n");
          	  	  	  goto bail_out;
				  	}
				  getrandom(stored_kek->next_kek_policy.encrypt_iv,
						  	stored_kek->encrypt_key_len);
				  getrandom(stored_kek->next_kek_policy.encrypt_key,
						  	stored_kek->encrypt_key_len);
			  }
			iv_to_send = stored_kek->next_kek_policy.encrypt_iv;
		    key_to_send = stored_kek->next_kek_policy.encrypt_key;
		  }
		 else
		   {
	  	  	  if (!stored_kek->encrypt_iv || !stored_kek->encrypt_key) 
			    {
         	      log_error ("gdoi_add_kd_payload: "
       	  		     	 	 "Missing KEK encryption key or IV\n");
          	  	  goto bail_out;
			   }
			 iv_to_send = stored_kek->encrypt_iv;
			 key_to_send = stored_kek->encrypt_key;
		  }
		  /*
		   * Prepend the IV
		   */
		  tmp_buf_len = 2 * stored_kek->encrypt_key_len;
		  tmp_buf = malloc(tmp_buf_len);
		  if (!tmp_buf)
            {
         	  log_error ("gdoi_add_kd_payload: "
       	  		     	 "malloc failed: %d bytes\n", tmp_buf_len);
          	  goto bail_out;
			}
		  memcpy(tmp_buf, iv_to_send, stored_kek->encrypt_key_len);
		  memcpy((tmp_buf+stored_kek->encrypt_key_len), 
				  	key_to_send, stored_kek->encrypt_key_len);
	  	  attr = attribute_set_var (attr,
					   				GDOI_ATTR_KD_KEK_SECRECY_KEY,
					   		  		tmp_buf, 
									tmp_buf_len);
		  free(tmp_buf);
		  tmp_buf = 0;
		  tmp_buf_len = 0;
	  	  break;

	    default:
          	  log_error ("gdoi_add_kd_payload: "
	             	 "Unsupported KEK Algorithm type %s",
				 	 stored_kek->encrypt_alg);
	  	  goto bail_out;
	  	  break;
		}

	  /*
       * Stuff the signature public key into the same attribute block.
 	   */
	  switch(stored_kek->sig_alg)
  		{
  		case GDOI_KEK_SIG_ALG_RSA:
  		  attr = attribute_set_var (attr,
  									GDOI_ATTR_KD_KEK_SIGNATURE_KEY,
						    		stored_kek->signature_key, 
						    		stored_kek->signature_key_len);
  		  break;
		default:
      		  log_error ("gdoi_add_kd_payload: "
             		 "Unsupported KEK Signature type %s",
			 		 stored_kek->sig_alg);
  		  goto bail_out;
		}
	  kd_pak_buf = gdoi_grow_buf(kd_pak_buf, &kd_pak_sz, 
			  					 attr_start, (attr - attr_start));
      if (!kd_pak_buf)
     	{
      	  goto bail_out;
		}
      free (attr_start);
	  attr_start = 0;
		
	  /* 
 	   * Fill in KD key packet length. 
 	   */
	  SET_GDOI_KD_PAK_LENGTH(kd_pak_buf, kd_pak_sz);

	  /*
   	   * Add the fully formed key packet to the KD payload
 	   */
      kd_buf = gdoi_grow_buf((u_int8_t *)kd_buf, &sz, kd_pak_buf, kd_pak_sz);
  	  /*
   	   * Update the running total of KD key packets.
   	   */
  	  total_kd_pak++;
    }

  /*
   * Add the TEK policies.
   *
   * The TEKs are stored in the "stored_kek" structure even if there is no KEK.
   * (Perhaps it should be renamed to "stored_group_policy".)
   */
  if (!stored_kek->send_exchange)
    {
      log_print ("gdoi_add_kd_payload: Exchange includeing SPIs not found");
      goto bail_out;
	}
  sa_exchange = stored_kek->send_exchange;

  /*
   * Only send KD key packets for SPIs found in the SPI list attached to
   * the exchange. This guarentees consistency between the payloads.
   */
  tekspi = TAILQ_FIRST (&ie->spis);
  while (tekspi)
	{
	  /*
	   * Find the sa structure for this SPI.
	   *
	   * Note that the SPI list is attached to "exchange", but the 
	   * SA list is attached to "sa_exchange".
	   */
	  proto = NULL;
  	  foundspi = FALSE;
  	  for (sa = TAILQ_FIRST (&sa_exchange->sa_list); sa; 
	  	   sa = TAILQ_NEXT (sa, next))
		{
		  proto = TAILQ_FIRST (&sa->protos);
		  if (proto && (proto->spi_sz[0] == tekspi->spi_sz) &&
		  	  !memcmp(proto->spi[0], tekspi->spi, tekspi->spi_sz))
			{
			  foundspi = TRUE;
			  break;
			}
		}
	  if (!foundspi)
	  	{
      	  log_print ("gdoi_add_kd_payload: SPI not found in SPI list");
      	  goto bail_out;
		}

  	  /*
   	   * The TEK keys are in the sa_exchange->sa_list->proto structure.
   	   *
  	   * Initialize the sa pointer. This appears to be the first 
  	   * convenient time to do so.
  	   */
      proto->sa = sa;
      kd_pak_sz = GDOI_KD_PAK_SPI_SIZE_OFF + GDOI_KD_PAK_SPI_SIZE_LEN;
  	  kd_pak_buf = calloc(1, kd_pak_sz);
  	  if (!kd_pak_buf)
        {
      	  log_error ("gdoi_add_kd_payload: calloc (%d) failed", 
  			   		 kd_pak_sz);
      	  goto bail_out;
    	}
  	  SET_GDOI_KD_PAK_KD_TYPE((u_int8_t *)kd_pak_buf, GDOI_KD_TYPE_TEK); 
  	  SET_GDOI_KD_PAK_SPI_SIZE((u_int8_t *)kd_pak_buf, proto->spi_sz[0]);
      		
  	  kd_pak_buf = gdoi_grow_buf(kd_pak_buf, &kd_pak_sz, 
  							     proto->spi[0], proto->spi_sz[0]);
 
	  /*
  	   * Find the keys in the proto and stuff them in an attribute block.
  	   */
      attr_start = attr = calloc(1, ATTR_SIZE);
      if (!attr)
      	{
     	  log_print ("gdoi_add_kd_payload: "
           		     "calloc(%d) failed", ATTR_SIZE);
		  goto bail_out;
  	  	}

	  /* 
  	   * Get this TEK's keys. 
	   */
	  memset((void *)&keys, 0, sizeof(struct gdoi_kd_decode_arg));
	  switch (proto->proto)
	  	{
		case IPSEC_PROTO_IPSEC_ESP:
		case IPSEC_PROTO_IPSEC_AH:
  	  	  if (gdoi_ipsec_get_tek_keys(&keys, proto))
  	  		{
       	  	  log_print ("gdoi_add_kd_payload: "
         	   	     "Error in getting IPSEC TEK keys!");
  	  		}
 
		  	/*
			 * In the case of a GDOI registration ("PULL_MODE") we may need
			 * to send SIDs. Since SIDs are allocated to a single GM, they are
			 * NEVER distributed in a rekey message.
		   	 * 
			 * We only need to send SIDs if there is at least one ESP 
			 * transform that is a counter mode transform.
		     */
		 	if (exchange->type == GDOI_EXCH_PULL_MODE)
			  {
		  		have_counter_modes = 
					gdoi_ipsec_is_counter_mode_tek(proto->proto, proto->id);
		  		if (have_counter_modes < 0)
		    	  {
			  		goto bail_out;
				  }
			  }

		  break;
#ifdef IEC90_5_SUPPORT
		case IPSEC_PROTO_IEC90_5:
  	  	  if (gdoi_iec90_5_get_tek_keys(&keys, proto))
  	  		{
       	  	  log_print ("gdoi_add_kd_payload: "
         	   	     "Error in getting IEC90-5 TEK keys!");
  	  		}
		  break;
#endif
#ifdef SRTP_SUPPORT
		case IPSEC_PROTO_SRTP:
  	  	  if (gdoi_srtp_get_tek_keys(&keys, proto))
  	  		{
       	  	  log_print ("gdoi_add_kd_payload: "
         	   	     "Error in getting SRTP TEK keys!");
  	  		}
		  break;
#endif
		default:
	      log_print ("gdoi_add_kd_payload: "
		             "Unsupported Protocol type %d", proto->proto);
		  goto bail_out;
	  }

  	  if (keys.sec_key_sz)
  	  	{
  	  	  attr = attribute_set_var (attr,
  	  		      GDOI_ATTR_KD_TEK_SECRECY_KEY,
  			      keys.sec_key, keys.sec_key_sz);
  	  	}	
  	  if (keys.int_key_sz)
  	  	{
  		  attr = attribute_set_var (attr, 
  					GDOI_ATTR_KD_TEK_INTEGRITY_KEY,
  				    keys.int_key, keys.int_key_sz);
  	  	}
#ifdef IEC90_5_SUPPORT
  	  if (keys.custom_kd_payload_sz)
  	  	{
  		  attr = attribute_set_var (attr, 
  					keys.custom_kd_payload_type,
  				    keys.custom_kd_payload, keys.custom_kd_payload_sz);
		  free(keys.custom_kd_payload);
		  keys.custom_kd_payload = 0;
		}
#endif
  	  kd_pak_buf = gdoi_grow_buf(kd_pak_buf, 
  	     				&kd_pak_sz, attr_start, (attr - attr_start));
	  if (!kd_pak_buf)
      	{
     	  goto bail_out;
  	  	}
      free (attr_start);
	  attr_start = 0;

  	  /* 
  	   * Fill in KD key packet length. 
  	   */
  	  SET_GDOI_KD_PAK_LENGTH(kd_pak_buf, kd_pak_sz);

  	  /*
  	   * Add the fully formed key packet to the KD payload
  	   */
  	  kd_buf = gdoi_grow_buf(kd_buf, &sz, kd_pak_buf, kd_pak_sz);

  	  /*
   	   * Update the running total of KD key packets.
  	   */
  	  total_kd_pak++;

	  /*
	   * Loop maintenance
	   */
      gdoi_remove_spi_from_list(ie, tekspi);
  	  tekspi = TAILQ_FIRST (&ie->spis);
  }

  /*
   * Add the SIDs, if needed.
   */
  if ((exchange->type == GDOI_EXCH_PULL_MODE) && have_counter_modes)
    {
	  u_int32_t sid_size = 16; /* Default SID size, if not configured */
	  u_int32_t num_gm_sids, max_sid_size;
	  int i;

	  /*
	   * Prepare the payload.
	   */
   	  kd_pak_sz = GDOI_KD_PAK_SPI_SIZE_OFF + GDOI_KD_PAK_SPI_SIZE_LEN;
  	  kd_pak_buf = calloc(1, kd_pak_sz);
  	  if (!kd_pak_buf)
	    {
   		  log_error ("gdoi_add_kd_payload: calloc (%d) failed", kd_pak_sz);
   	  	  goto bail_out;
   		}
	  SET_GDOI_KD_PAK_KD_TYPE(kd_pak_buf, GDOI_KD_TYPE_SID); 
  	  SET_GDOI_KD_PAK_SPI_SIZE(kd_pak_buf, 0);

      attr_start = attr = calloc(1, ATTR_SIZE);
      if (!attr)
      	{
     	  log_print ("gdoi_add_kd_payload: calloc(%d) failed", ATTR_SIZE);
		  goto bail_out;
  	  	}

	  /*
	   * Check for the SID size (in bits) and send it.
	   */
  	  conf_field = conf_get_str (exchange->policy, "GROUP-POLICY");
  	  if (conf_field)
    	{
  			str = conf_get_str (conf_field, "SID-SIZE");
  			if (str) 
    		  {
	  			sid_size = atoi(str); 
			  }
		}
  	  attr = attribute_set_basic (attr, GDOI_ATTR_KD_SID_NUM_BITS, sid_size);

	  /*
	   * Send as many unique SIDs are are needed -- either as many as the GM
	   * asked for, or send them one if they did not ask for any.
	   *
	   * This KS has a simple policy for dispensing unique SIDs: Start a
	   * counter at zero, and distribute SIDs until they run out. When the 
	   * counter reaches its max, a less naive KS implementation would reset
	   * the counter, and force the GMs to re-register and get new SIDs.
	   */
	  max_sid_size = ((u_int64_t)1 << sid_size) - 1;
	  num_gm_sids = (ie->num_sids > 1)? ie->num_sids : 1;
	  if ((stored_kek->sid_counter + num_gm_sids) < max_sid_size)
		{
	  	  for (i=0; i<num_gm_sids; i++)
			{
  	  	  	  attr = attribute_set_var (attr, GDOI_ATTR_KD_SID_VALUE, 
				  				    (u_int8_t *)&stored_kek->sid_counter, 4);
	  	  	  stored_kek->sid_counter++;
			}
		}
	  else
	    {
		  log_print("gdoi_add_kd_payload: Not enough SID values to send!");
		  goto bail_out;
		}

	  kd_pak_buf = gdoi_grow_buf(kd_pak_buf, &kd_pak_sz, 
			  					 attr_start, (attr - attr_start));
      if (!kd_pak_buf)
     	{
      	  goto bail_out;
		}
      free (attr_start);
	  attr_start = 0;

  	  SET_GDOI_KD_PAK_LENGTH(kd_pak_buf, kd_pak_sz);
  	  kd_buf = gdoi_grow_buf(kd_buf, &sz, kd_pak_buf, kd_pak_sz);
  	  total_kd_pak++;
	} 

  SET_GDOI_KD_NUM_PACKETS (kd_buf, total_kd_pak);

  if (message_add_payload (msg, ISAKMP_PAYLOAD_KD, kd_buf, sz, 1))
    goto bail_out;
  kd_buf = 0;

  return 0;
  
  bail_out:
    free(kd_buf);
	free(seq_buf);
    free(attr_start);
	gdoi_clear_spi_list(exchange);
    return -1;
}

static int responder_send_HASH_SEQ_KD (struct message *msg)
{
  struct ipsec_sa *isa = msg->isakmp_sa->data;
  struct exchange *exchange = msg->exchange;
  struct gdoi_exch *ie = exchange->data;
  struct hash *hash = hash_get (isa->hash);
  struct gdoi_kek *stored_kek;
  u_int8_t *seq_buf = 0;
  size_t sz;

  /*
   * Add HASH payload
   */
  if (!ipsec_add_hash_payload (msg, hash->hashsize)) {
    return -1;
  }

  /*
   * Add SEQ payload if there's a rekey policy for this message
   */
  stored_kek = gdoi_get_kek(ie->id_gdoi, ie->id_gdoi_sz, 0);
  if (!stored_kek)
  	{
	  return -1;
	}

  if (!(stored_kek->flags & USE_EXCH_ONLY)) {
  	  sz = GDOI_SEQ_SEQ_NUM_OFF + GDOI_SEQ_SEQ_NUM_LEN;
  	  seq_buf = calloc (1, sz);
  	  if (!seq_buf)
    	{
      	  log_error ("responder_send_HASH_SEQ_KD: calloc (%d) failed", sz);
      	  goto bail_out;
    	}
  	  SET_GDOI_SEQ_SEQ_NUM(seq_buf, stored_kek->current_seq_num);
      log_print ("SENT SEQ # of: %d (PULL)", stored_kek->current_seq_num);
  	  if (message_add_payload (msg, ISAKMP_PAYLOAD_SEQ, seq_buf, sz, 1)) 
	    {
    	  return -1;
	  	}	
    }

  /*
   * Add KD payload
   */
  if (gdoi_add_kd_payload(msg)) 
    {
	  return -1;
    }
   
  /*
   * Fill in the hash for the HASH payload.
   */
  if (group_fill_in_hash (msg, INC_I_NONCE, INC_R_NONCE)) 
    {
    	return -1;
  	}

  if (exchange->type == GDOI_EXCH_PULL_MODE)
  	{
  	  if (stored_kek && !(stored_kek->flags & USE_EXCH_ONLY) && 
		  !stored_kek->tek_lifetime_ev)
    	{
	  	  log_print("responder_send_HASH_SEQ_KD: Setup rekey message");
		  /*
		   * Start the KEK rekey timer here.
		   */
		  gdoi_kek_rekey_start(stored_kek);
	  	  gdoi_rekey_start(stored_kek); 
		}
	}

  return 0;

  bail_out:
	if (seq_buf) {
	  free(seq_buf);
    }
    return -1;
}
