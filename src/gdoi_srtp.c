/* $Id: gdoi_srtp.c,v 1.6.4.2 2011/12/05 20:31:07 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/Attic/gdoi_srtp.c,v $ */

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
 * The license applies to all software incorporated in the "Cisco GDOI reference
 * implementation" except for those portions incorporating third party software 
 * specifically identified as being licensed under separate license. 
 *  
 *  
 * The Cisco Systems Public Software License, Version 1.0 
 * Copyright (c) 2001 Cisco Systems, Inc. All rights reserved.
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
#include <netinet/in.h>
#include <arpa/inet.h>

#include "attribute.h"
#include "conf.h"
#include "connection.h"
#include "doi.h"
#include "exchange.h"
#include "hash.h"
#include "gdoi_phase2.h"
#include "log.h"
#include "math_group.h"
#include "message.h"
#include "prf.h"
#include "sa.h"
#include "transport.h"
#include "util.h"
#include "gdoi_fld.h"
#include "gdoi_num.h"
#include "gdoi_srtp.h"
#include "gdoi_srtp_attr.h"
#include "srtp_num.h"
#include "ipsec_num.h"
#include "gdoi.h"

#define AES_128_LENGTH 16
#define SALT_112_LENGTH 14

#define SRC 1
#define DST 2

#define ATTR_SIZE (50 * ISAKMP_ATTR_VALUE_OFF)

/*
 * BEW: Temp extern. ID handling should be moved to a new file.
 */
extern u_int8_t *gdoi_build_tek_id (char *section, size_t *sz);

int srtp_decode_attribute (u_int16_t type, u_int8_t *value, u_int16_t len,
						   void *arg)
{
  struct srtp_proto *sa = (struct srtp_proto *) arg;

  switch (type)
    {
	case SRTP_ATTR_CIPHER:
	  sa->cipher_type = decode_16(value);
	  break;
	case SRTP_ATTR_CIPHER_MODE:
	  sa->cipher_mode = decode_16(value);
	  break;
	case SRTP_ATTR_CIPHER_KEY_LENGTH:
	  sa->cipher_key_length = decode_16(value);
	  break;
	default:
      log_print ("srtp_decode_attribute: Attribute not valid: %d", type);
	  return -1;
	}

  return 0;
}

/*
 * Group member side (decode & store TEK values)
 * Key server side (save a copy of the SA in his own sa list for later use by 
 * the rekey message)
 *
 * Decode the SRTP type TEK and stuff into the SA.
 */
int
gdoi_srtp_decode_tek (struct message *msg, struct sa *sa, u_int8_t *srtp_tek,
			  		  size_t srtp_tek_len, int create_proto)
{
  u_int8_t *cur_p;
  struct proto *proto = NULL;
  struct srtp_proto *sproto = NULL;
  int id_type, id_len, temp_len;
  
  /*
   * Validate the SA.
   */
  if (!sa)
    {
  	  log_error ("group_decode_esp_tek: No sa's in list!");
  	  goto clean_up;
	}

  if (create_proto)
  	{
  	  if (gdoi_setup_sa (sa, &proto, IPSEC_PROTO_SRTP,
						 sizeof(struct srtp_proto)))
		{
	  	  goto clean_up;
		}
	}
  else
    {
	  proto = TAILQ_LAST(&sa->protos, proto_head);
	}

  /*
   * Stuff the SRTP policy in the proto structure. (Can't use sa->data because
   * that is initialized in sa_create(). sa->data is unused for SRTP.)
   */
  sproto = (struct srtp_proto *) proto->data;

  /*
   * Get src_id fields
   * We can use the ESP fields & types since they are defined identically.
   */
  cur_p = srtp_tek;
  id_type = GET_GDOI_SA_ID_TYPE(cur_p);
  id_len = GET_GDOI_SA_ID_DATA_LEN(cur_p);
  sproto->sport = ntohs(GET_GDOI_SA_ID_PORT(cur_p));
  switch (id_type)
    {
	case IPSEC_ID_IPV4_ADDR:
	  if (id_len != 4)
		{
  	  	  log_error ("gdoi_srtp_decode_tek: Invalid length for src IP addr: %d",
				   id_len);
  	  	  goto clean_up;
	    }
	  sproto->src_net = htonl(decode_32(cur_p+GDOI_SA_ID_DATA_OFF));
	  sproto->src_mask = htonl(0xffffffff);
	  break;
	case IPSEC_ID_IPV4_ADDR_SUBNET:
	  if (id_len != 8)
		{
  	  	  log_error ("gdoi_srtp_decode_tek: Invalid length for src IP subnet:"
		  			 "%d", id_len);
  	  	  goto clean_up;
	    }
	  sproto->src_net = htonl(decode_32(cur_p+GDOI_SA_ID_DATA_OFF));
	  sproto->src_mask = htonl(decode_32(cur_p+GDOI_SA_ID_DATA_OFF+4));
	  break;
	default:
  	  log_error ("gdoi_srtp_decode_tek: Unsupported src id type: %d", id_type);
  	  goto clean_up;
	}
  cur_p = cur_p + GDOI_SA_ID_DATA_OFF + id_len;
	  
  /*
   * Get dst_id fields. Only type ID_IPV4_ADDR is reasonable.
   */
  sproto->dport = ntohs(GET_GDOI_SA_ID_PORT(cur_p));
  id_len = GET_GDOI_SA_ID_DATA_LEN(cur_p);
  if (id_len != 4)
    {
  	  log_error ("gdoi_srtp_decode_tek: Invalid length for dst IP addr: %d",
  		          id_len);
  	  goto clean_up;
    }
  sproto->dst_net = htonl(decode_32(cur_p + GDOI_SA_ID_DATA_OFF));
  sproto->dst_mask = htonl(0xffffffff);
  cur_p = cur_p + GDOI_SA_ID_DATA_OFF + id_len;

  /*
   * Get Replay Window, KD Rate, SRTP Lifeime, SRTCP Lifetime
   */
  sproto->replay_window  = *cur_p++;
  sproto->kd_rate        = *cur_p++;
  sproto->srtp_lifetime  = *cur_p++;
  sproto->srtcp_lifetime = *cur_p++;

  /*
   * Get SPI
   */
  proto->spi_sz[0]=*cur_p++;
  proto->spi[0]= malloc(proto->spi_sz[0]);
  if (!proto->spi[0])
    {
      log_print ("gdoi_srtp_decode_tek: malloc failed (%d)", proto->spi_sz[0]);
      goto clean_up;
    }
  memcpy(proto->spi[0], cur_p, proto->spi_sz[0]);

  switch(proto->spi_sz[0]) {
	case 2:
	  log_print(" SPI found (SA) %u (%d) (%#x) for sa %#x", 
					decode_16(proto->spi[0]), decode_16(proto->spi[0]), 
					decode_16(proto->spi[0]), sa);
	   break;
	case 4:
	  log_print(" SPI found (SA) %u (%d) (%#x) for sa %#x", 
					decode_32(proto->spi[0]), decode_32(proto->spi[0]), 
					decode_32(proto->spi[0]), sa);
	   break;
	 default:
	  	log_print ("install_tek_keys: Unsupported spi size: %d", proto->spi[0]);
		break;
  }
  cur_p += proto->spi_sz[0];

  /*
   * BEW: HACK! HACK! HACK!
   * Assuming  128 bit AES & 112 bit master salt. Need to stuff it into the
   * srtp_proto now. Normally it would come from the Cipher Suite.
   *
   * This is used in KD payload processing to verify that the length of the keys
   * received in the KD payload are correct.
   */
  sproto->master_key_len = AES_128_LENGTH;
  sproto->master_salt_key_len = SALT_112_LENGTH;

  temp_len = srtp_tek_len - (cur_p - srtp_tek);

  attribute_map (cur_p, temp_len, srtp_decode_attribute, sproto);

  return 0;
 
clean_up:
  if (proto)
    {
  	  proto_free(proto);
	}
  return -1;
}
      
/*
 * Key server side
 * Find the TEK-specific policy for an SRTP type TEK.
 */
int gdoi_srtp_set_policy (char *conf_field, struct message *msg,
			  struct exchange *sa_exchange)
{
  struct sa *sa;
  struct proto *proto;
  struct srtp_proto *sproto;
  char *src_id, *dst_id;
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
   	  log_error ("gdoi_ipsec_get_policy: No sa's in list!");
   	  goto bail_out;
	}
 
  /*
   * Initialize the SA
   */
  if (gdoi_setup_sa (sa, &proto, IPSEC_PROTO_SRTP, sizeof(struct srtp_proto)))
	{
	  goto bail_out;
	}
  sproto = proto->data;

  /*
   * Start with the src/dst fields.
   */
  src_id = conf_get_str (conf_field, "Src-ID");
  if (!src_id) 
	{
	  log_print ("gdoi_ipsec_get_policy: "
                 "Src-ID missing");
	  goto bail_out;
    }
  if (gdoi_get_id (src_id, &id, &addr, &mask, &port))
  	{
   	  goto bail_out;
   	}
  sproto->src_net = htonl(addr.s_addr);
  sproto->src_mask = htonl(mask.s_addr);
  sproto->sport = ntohs(port);

  dst_id = conf_get_str (conf_field, "Dst-ID");
  if (!dst_id)
    {
      log_print ("gdoi_ipsec_get_policy: "
           	      "Dst-ID missing");
	  goto bail_out;
	}
  if (gdoi_get_id (dst_id, &id, &addr, &mask, &port))
  	{
   	  goto bail_out;
   	}
  sproto->dst_net = htonl(addr.s_addr);
  sproto->dst_mask = htonl(mask.s_addr);
  sproto->dport = ntohs(port);

  /*
   * Replay Window
   */
  sproto->replay_window=16; /* BEW: Temp hardcoded value */
  
  /*
   * KD Rate
   */
  sproto->kd_rate=1; /* BEW: Temp hardcoded value */

  /*
   * SRTP Lifetime
   */
  sproto->srtp_lifetime=16; /* BEW: Temp hardcoded value */

  /*
   * SRTCP Lifetime
   */
  sproto->srtcp_lifetime=16; /* BEW: Temp hardcoded value */

	  /*
	   * BEW: Assume SPI is 2 bytes.
	   */
	  proto->spi_sz[0] = 2;
	  proto->spi[0] = malloc(proto->spi_sz[0]);
	  if (!proto->spi[0])
		{
		  log_error ("gdoi_srtp_get_policy: malloc failure -- SPI (%d bytes)",
				  	 proto->spi_sz[0]);
		  goto bail_out;
		}
	  
	  /*
	   * BEW: Choose a random SPI for now.
	   *
	   * Write the SPI length & SPI.
	   */
	  getrandom(proto->spi[0], proto->spi_sz[0]);

	  /*
	   * BEW: Generate AES keys irrespective of Options and Crypto Suite for 
	   *      now.
	   */
	  sproto->master_key_len = AES_128_LENGTH;
	  sproto->master_key = malloc(sproto->master_key_len);
	  if (!sproto->master_key)
		{
		  log_print ("gdoi_srtp_get_policy: malloc failed: master key (%d)",
				  	 sproto->master_key_len);
		  goto bail_out;
		}
	  getrandom(sproto->master_key, sproto->master_key_len);

	  sproto->master_salt_key_len = SALT_112_LENGTH;
	  sproto->master_salt_key = malloc(sproto->master_salt_key_len);
	  if (!sproto->master_salt_key)
		{
		  log_print ("gdoi_srtp_get_policy: malloc failed: master key (%d)",
				  	 sproto->master_salt_key_len);
		  goto bail_out;
		}
	  getrandom(sproto->master_salt_key, sproto->master_salt_key_len);

  return 0;

bail_out:
    return -1;
}

/*
 * Group member side
 * Validate and install keys gotten from the KD in the sproto structure.
 */
int
gdoi_srtp_install_keys (struct proto *proto, struct gdoi_kd_decode_arg *keys)
{
  struct srtp_proto *sproto;

  if (proto->proto != IPSEC_PROTO_SRTP)
    {
      log_error ("gdoi_srtp_install_keys: SRTP SA expected, got %d",
	  			 proto->proto);
      return -1;
	}

  sproto = (struct srtp_proto *) proto->data;
  if (!sproto)
    {
      log_error ("gdoi_srtp_install_keys: SRTP SA TEK data missing");
      return -1;
    }

  /*
   * Validate that the key length is correct & copy them.
   */
  if (keys->sec_key_sz != 
	  (size_t)(sproto->master_key_len + sproto->master_salt_key_len))
    {
	  log_error ("gdoi_srtp_install_tek_keys:"
	  			 "Wrong key length! Expected: %d, Actual: %d",
				 sproto->master_key_len+sproto->master_salt_key_len, 
				 keys->sec_key_sz);
	  return -1;
	}

  /*
   * Split the keying material into their repsective parts.
   */
  sproto->master_key = malloc(sproto->master_key_len);
  if (!sproto->master_key)
	{
	  log_print ("gdoi_srtp_get_policy: malloc failed: master key (%d)",
			  	 sproto->master_key_len);
	  return -1;
	}
  memcpy(sproto->master_key, keys->sec_key, sproto->master_key_len);
  
  sproto->master_salt_key = malloc(sproto->master_salt_key_len);
  if (!sproto->master_salt_key)
	{
	  log_print ("gdoi_srtp_get_policy: malloc failed: master key (%d)",
			  	 sproto->master_salt_key_len);
	  free(sproto->master_key);
	  return -1;
	}
  memcpy(sproto->master_salt_key, (keys->sec_key+sproto->master_key_len), 
		 sproto->master_key_len);

  return 0;
}

#ifdef NOTYET
/*
 * Group member side
 * Finalize the exchange -- send the key & policy info to the SRTP app.
 */
int
gdoi_srtp_deliver_keys (struct message *msg, struct sa *sa)
{
  /*
   * Give the keys to the client s/w.
   */
  srtp_deliver_keys (sa);
  return 0;
}
#endif
/*
 * Translate keys from the SRTP proto into a generic structure
 */
int
gdoi_srtp_get_tek_keys (struct gdoi_kd_decode_arg *keys, struct proto *proto)
{
 struct srtp_proto *sproto= (struct srtp_proto *) proto->data;

  /*
   * Concatenate the master key and master salt key.
   */
  keys->sec_key_sz = sproto->master_key_len + sproto->master_salt_key_len;
  keys->int_key_sz = 0;

  if (keys->sec_key_sz)
  	{
  	  keys->sec_key = malloc(keys->sec_key_sz);
  	  if (!keys->sec_key)
  		{
	  	  return -1;
		}
  	  memcpy(keys->sec_key, sproto->master_key, sproto->master_key_len);
  	  memcpy(keys->sec_key+sproto->master_key_len, 
			sproto->master_salt_key, sproto->master_salt_key_len);
	}
 
  return 0;
}

/*
 * Out of an SA build the ID fields of a TEK payload. The caller is 
 * responsible for freeing the payload.
 */
static u_int8_t *
gdoi_srtp_build_tek_id_from_sa (struct sa *sa, int srcdst, size_t *sz)
{
  struct proto *proto = TAILQ_FIRST (&sa->protos);
  struct srtp_proto *sproto= (struct srtp_proto *) proto->data;
  struct in_addr addr, mask;
  u_int16_t port;
  int id_type = 0;

  switch (srcdst)
    {
	case SRC:
	  port = sproto->sport;
	  addr.s_addr = sproto->src_net;
	  mask.s_addr = sproto->src_mask;
	  break;
	case DST:
	  port = sproto->dport;
	  addr.s_addr = sproto->dst_net;
	  mask.s_addr = sproto->dst_mask;
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
int
gdoi_srtp_get_policy_from_sa (struct sa *sa, u_int8_t **ret_buf,
                           	   size_t *ret_buf_sz)
{
  u_int8_t *srtp_tek_buf = 0;
  u_int8_t *buf = 0;
  size_t sz, srtp_tek_sz;
  u_int8_t *attr, *attr_start;
  struct proto *proto;
  struct srtp_proto *sproto;

  proto = TAILQ_FIRST (&sa->protos);
  sproto = proto->data;

  /*
   * Set the SRC/DST ID info
   */
  srtp_tek_sz = 0;
  srtp_tek_buf = NULL;
  buf = gdoi_srtp_build_tek_id_from_sa (sa, SRC, &sz);
  if (!buf)
    {
      goto bail_out;
    }
  srtp_tek_buf = gdoi_grow_buf(srtp_tek_buf, &srtp_tek_sz, buf, sz);
  free(buf);
  buf = NULL;
  buf = gdoi_srtp_build_tek_id_from_sa (sa, DST, &sz);
  if (!buf)
    {
      goto bail_out;
    }
  srtp_tek_buf = gdoi_grow_buf(srtp_tek_buf, &srtp_tek_sz, buf, sz);
  free(buf);
  buf = NULL;

  /* 
   * Replay window, KD rate, SRTP lifetime, SRTCP lifetime
   * 1 byte each
   */
  srtp_tek_buf = gdoi_grow_buf(srtp_tek_buf, &srtp_tek_sz, 
		  					   &sproto->replay_window, 1);
  srtp_tek_buf = gdoi_grow_buf(srtp_tek_buf, &srtp_tek_sz, 
		  					   &sproto->kd_rate, 1);
  srtp_tek_buf = gdoi_grow_buf(srtp_tek_buf, &srtp_tek_sz, 
		  					   &sproto->srtp_lifetime, 1);
  srtp_tek_buf = gdoi_grow_buf(srtp_tek_buf, &srtp_tek_sz, 
		  					   &sproto->srtcp_lifetime, 1);

  /*
   * Write out the SPI size and SPI for this TEK.
   */
  srtp_tek_buf = gdoi_grow_buf(srtp_tek_buf, &srtp_tek_sz,
			  				   &proto->spi_sz[0], 1);
  srtp_tek_buf = gdoi_grow_buf(srtp_tek_buf, &srtp_tek_sz,
			  				   (u_int8_t *)proto->spi[0], proto->spi_sz[0]);

  /*
   * BEGIN ATTRIBUTE PROCESSING
   * Allocate a block for building attributes. It's sized large enough
   * so that we think it will avoid buffer overflows....
   */
  attr_start = attr = calloc(1, ATTR_SIZE); 
  if (!attr)
    {
  	  log_print ("gdoi_srtp_get_policy: "
              	 "calloc(%d) failed", ATTR_SIZE);
  	  goto bail_out;
	}

  /*
   * Put the cipher into the payload as attributes
   */
  attr = attribute_set_basic (attr, SRTP_ATTR_CIPHER, sproto->cipher_type);
  attr = attribute_set_basic (attr, SRTP_ATTR_CIPHER_MODE,
  							  		sproto->cipher_mode);
  attr = attribute_set_basic (attr, SRTP_ATTR_CIPHER_KEY_LENGTH,
  							  		sproto->cipher_key_length);
  /*
   * Add the attributes to the tek payload
   */
  srtp_tek_buf = gdoi_grow_buf(srtp_tek_buf, &srtp_tek_sz, attr_start, 
                               (attr - attr_start));
  free (attr_start);
  if (!srtp_tek_buf)
    {
      goto bail_out;
	}

  *ret_buf = srtp_tek_buf;
  *ret_buf_sz = srtp_tek_sz;

  return 0;

bail_out:
    if (buf)
      {
        free (buf);
      }
    gdoi_free_attr_payloads();
    return -1;
}

u_int8_t *
gdoi_srtp_add_attributes (u_int8_t *attr, struct sa *sa)
{
  struct proto *proto = NULL;
  struct srtp_proto *sproto = NULL;

  proto = TAILQ_LAST(&sa->protos, proto_head);
  sproto = (struct srtp_proto *) proto->data;

  attr = attribute_set_basic (attr, SRTP_REPLAY_WINDOW, sproto->replay_window);
  attr = attribute_set_basic (attr, SRTP_KD_RATE, sproto->kd_rate);
  attr = attribute_set_basic (attr, SRTP_LIFETIME, sproto->srtp_lifetime);
  attr = attribute_set_basic (attr, SRTP_SRTCP_LIFETIME, sproto->srtp_lifetime);

  if (!sproto->master_key) 
    {
  	  log_print ("gdoi_srtp_add_attributes: Master key missing!\n");
	}
  else 
    {
  	  attr = attribute_set_var (attr, SRTP_MASTER_KEY, 
	  		    sproto->master_key,
			    sproto->master_key_len);
    }
  if (!sproto->master_salt_key) 
    {
  	  log_print ("gdoi_srtp_add_attributes: Master Salt key missing!\n");
	}
  else 
    {
      attr = attribute_set_var (attr, SRTP_MASTER_SALT_KEY,
	  		    sproto->master_salt_key,
			    sproto->master_salt_key_len);
	}

  return attr;
}
