/* $Id: gdoi_iec90_5.c,v 1.1.2.1 2011/12/12 20:43:47 bew Exp $ */
/* $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/Attic/gdoi_iec90_5.c,v $ */

/* 
 * The license applies to all software incorporated in the "Cisco GDOI reference
 * implementation" except for those portions incorporating third party software 
 * specifically identified as being licensed under separate license. 
 *  
 *  
 * The Cisco Systems Public Software License, Version 1.0 
 * Copyright (c) 2011 Cisco Systems, Inc. All rights reserved.
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
#include "message.h"
#include "prf.h"
#include "sa.h"
#include "transport.h"
#include "util.h"
#include "gdoi_fld.h"
#include "ipsec_num.h"
#include "gdoi_num.h"
#include "gdoi_iec90_5.h"
#include "iec90_5_num.h"
#include "iec90_5_fld.h"
#include "gdoi.h"
#include "gdoi_app_iec90_5_attr.h"

int
iec90_5_get_id (char *section, size_t *id_sz, u_int8_t **buf)
{
  int oid_type;
  char *oid, *address;
  struct in_addr ip_addr;
  size_t id_asn_sz, id_buf_sz;
  u_int8_t *id_buf;

  oid = conf_get_str (section, "OID");
  oid_type = constant_value (iec90_5_id_cst, oid);

  switch (oid_type) 
  	{
	  case IEC90_5_ID_61850_UDP_ADDR_GOOSE:
      	address = conf_get_str (section, "Address");
      	if (!address)
		  {
	  	 	log_print ("iec90_5_get_id: section %s has no \"Address\" tag",
		   		 		section);
			return -1;
		  }
      	if (!inet_aton (address, &ip_addr))
		  {
	  	 	log_print ("iec90_5_get_id: invalid address %s in section %s", 
						section, address);
	  	  	return -1;
		  }
		break;
	default:
	  log_print ("iec90_5_get_id: Unkonwn or Unsupported IEC90_5 OID: %d\n", 
			  	 oid_type);
	  return -1;
	 }

  /*
   * Format ID payload. See Clause 11.4.2 ("Identification Paylod") of 90-5.
   * NOTE: This doesn't actually  match that clause -- needs work.
   */
  id_asn_sz = strlen(OID_61850_UDP_ADDR_GOOSE);
  id_buf_sz = IEC90_5_ID_SZ + id_asn_sz;
  id_buf = calloc(1, id_buf_sz);
  if (!id_buf) {
	log_print ("iec90_5_get_id: Calloc failed for %d bytes\n", id_buf_sz);
	return -1;
  }
  SET_IEC90_5_ID_ID(id_buf, 0xa1);
  SET_IEC90_5_ID_PAYLOAD_LEN(id_buf, id_buf_sz);
  SET_IEC90_5_ID_TAG(id_buf, 0x80);
  SET_IEC90_5_ID_OID_LEN(id_buf, id_asn_sz);
  memcpy(&id_buf[IEC90_5_ID_SZ], OID_61850_UDP_ADDR_GOOSE, id_asn_sz);

  *buf = id_buf;
  *id_sz = id_buf_sz;

  return 0;
}

int
iec90_5_validate_id_information (u_int8_t *buf)
{
	LOG_DBG ((LOG_MESSAGE, 40,
			  "iec90_5_validate_id_information: Got an IEC90-5 ID"));

	/*
	 * The ID payload is so complicated that it probably warrants some good
	 * format validation here.
	 */

	return 0;
}

/*
 * Key server side
 * Find the TEK-specific policy for an IEC90-5 type TEK.
 */
int gdoi_iec90_5_set_policy (char *conf_field, struct message *msg,
			  struct exchange *sa_exchange, u_int8_t *id_gdoi, 
			  u_int16_t id_gdoi_sz)
{
  struct sa *sa;
  struct proto *proto;
  struct iec90_5_proto *iec_proto;
  u_int8_t *iec90_5_id;

  /*
   * Find the sa. The last SA in the list was just created for our use.
   */
  sa = TAILQ_LAST (&sa_exchange->sa_list, sa_head);
  if (!sa)
	{
   	  log_error ("gdoi_iec90_5_set_policy: No sa's in list!");
   	  goto bail_out;
	}
 
  /*
   * Initialize the SA
   */
  if (gdoi_setup_sa (sa, &proto, IPSEC_PROTO_IEC90_5, sizeof(struct iec90_5_proto)))
	{
	  goto bail_out;
	}
  iec_proto = proto->data;

  /*
   * TEK will need to include the ID ASN.1 included in the 1st GDOI message.
   * Note: Need to adjust the starting point of the macros to the start of 
   *       the IEC90-5 specific ID data.
   */
  iec90_5_id = id_gdoi + 8;
  iec_proto->oid_sz = GET_IEC90_5_ID_OID_LEN(iec90_5_id);
  iec_proto->oid = calloc(1, iec_proto->oid_sz);
  if (!iec_proto->oid) {
	log_error ("gdoi_iec90_5_set_policy: Malloc failed %d bytes.");
	goto bail_out;
  }
  memcpy(iec_proto->oid, &iec90_5_id[IEC90_5_ID_SZ], iec_proto->oid_sz);

  /*
   * BEW: Hardcode policy for now. It shoud be read in from the configuration.
   */
  iec_proto->auth_alg = GDOI_KEK_HASH_ALG_SHA;
  iec_proto->auth_key_size = HMAC_SHA_LENGTH;
  iec_proto->next_auth_alg = 0;
  iec_proto->next_auth_key_size = 0;

  /*
   * BEW: Assume SPI is 1 byte.
   *      Also, just send key_id NOT next key_id for now.
   */
  proto->spi_sz[0] = 1;
  proto->spi[0] = malloc(proto->spi_sz[0]);
  if (!proto->spi[0])
	{
	  log_error ("gdoi_iec90_5_set_policy: malloc failure -- SPI (%d bytes)",
			  	 proto->spi_sz[0]);
	  goto bail_out;
	}
  /*
   * Choose a random SPI 
   *
   * Write the SPI length & SPI.
   */
  getrandom(proto->spi[0], proto->spi_sz[0]);

  iec_proto->auth_key = malloc(iec_proto->auth_key_size);
  if (!iec_proto->auth_key)
	{
	  log_print ("gdoi_iec90_5_set_policy: malloc failed: auth key (%d)",
			  	 iec_proto->auth_key_size);
	  goto bail_out;
	}
  getrandom(iec_proto->auth_key, iec_proto->auth_key_size);

  return 0;

bail_out:
    return -1;
}

int
gdoi_iec90_5_get_policy_from_sa (struct sa *sa, u_int8_t **ret_buf,
                           	   size_t *ret_buf_sz)
{
  u_int8_t *iec90_5_tek_buf = 0;
  u_int8_t *iec90_5_tek_p2_buf = 0;
  size_t iec90_5_tek_sz;
  struct proto *proto;
  struct iec90_5_proto *iec_proto;
  char keyid;

  proto = TAILQ_FIRST (&sa->protos);
  iec_proto = proto->data;

  iec90_5_tek_sz = IEC90_5_TEK_P1_SZ + iec_proto->oid_sz + IEC90_5_TEK_P2_SZ;
  iec90_5_tek_buf = calloc(1, iec90_5_tek_sz);
  if (!iec90_5_tek_buf) {
	  log_print ("gdoi_iec90_5_get_policy_from_sa: Failed to get %d bytes for "
			     "IEC90-5 TEK payload", iec90_5_tek_sz);
	  return -1;
  }

  /*
   * IEC90-5 paylaod (approximtely)
   */

  SET_IEC90_5_TEK_P1_TAG(iec90_5_tek_buf, 0x80);
  SET_IEC90_5_TEK_P1_OID_SZ(iec90_5_tek_buf, iec_proto->oid_sz);
  memcpy(iec90_5_tek_buf+IEC90_5_TEK_P1_SZ, iec_proto->oid, iec_proto->oid_sz);
  iec90_5_tek_p2_buf = iec90_5_tek_buf + IEC90_5_TEK_P1_SZ + iec_proto->oid_sz;
  if (1 == proto->spi_sz[0]) {
	  keyid =  *proto->spi[0];
	  SET_IEC90_5_TEK_P2_CUR_KEY_ID(iec90_5_tek_p2_buf, keyid);
  } else {
	  log_print ("gdoi_iec90_5_get_policy_from_sa: Improper SPI size %d!",
			  	 proto->spi_sz[0]);
	  return -1;
  }
  /*
   * NOTE: The same values below need to be sent in the KD paylaod!
   */
  SET_IEC90_5_TEK_P2_LT_ID(iec90_5_tek_p2_buf, 1);
  SET_IEC90_5_TEK_P2_LT_V(iec90_5_tek_p2_buf, 1);
  SET_IEC90_5_TEK_P2_RES(iec90_5_tek_p2_buf, 0);
  SET_IEC90_5_TEK_P2_LT(iec90_5_tek_p2_buf, 3600);
  SET_IEC90_5_TEK_P2_AUTH_ALG_ID(iec90_5_tek_p2_buf, 5);
  SET_IEC90_5_TEK_P2_AUTH_ALG(iec90_5_tek_p2_buf, 2);
  SET_IEC90_5_TEK_P2_KEY_LEN(iec90_5_tek_p2_buf, iec_proto->auth_key_size);

  /* 
   * I don't get how the AES bits work when HMAC is used so am omitting them.
   * Also omitting the next key stuff.
   */

  *ret_buf = iec90_5_tek_buf;
  *ret_buf_sz = iec90_5_tek_sz;

  return 0;

}

/*
 * Group member side (decode & store TEK values) Decode the SRTP type TEK 
 * and stuff into the SA.
 */
int
gdoi_iec90_5_decode_tek (struct message *msg, struct sa *sa, 
			 u_int8_t *iec90_5_tek, size_t iec90_5_tek_len, 
			 int create_proto)
{
  u_int8_t *iec90_5_p2_tek;
  struct proto *proto = NULL;
  struct iec90_5_proto *iec_proto = NULL;
  u_int8_t tmp_1byte;
  
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
  	  if (gdoi_setup_sa (sa, &proto, IPSEC_PROTO_IEC90_5,
						 sizeof(struct iec90_5_proto)))
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
  iec_proto = (struct iec90_5_proto *) proto->data;

  /*
   * Process 1st part of TEK (OID)
   */
  tmp_1byte = GET_IEC90_5_TEK_P1_TAG(iec90_5_tek);
  if (0x80 != tmp_1byte) {
      log_print ("gdoi_iec90_5_decode_tek: Wrong TEK ID %d\n", tmp_1byte);
      goto clean_up;
  }
  iec_proto->oid_sz = GET_IEC90_5_TEK_P1_OID_SZ(iec90_5_tek);
  iec_proto->oid = calloc(1, iec_proto->oid_sz);
  if (!iec_proto->oid) {
      log_print ("gdoi_iec90_5_decode_tek: calloc failed for OID size (%d)",
	      	 iec_proto->oid_sz);
      goto clean_up;
  }
  memcpy(iec_proto->oid, iec90_5_tek+IEC90_5_TEK_P1_SZ, iec_proto->oid_sz);

  /*
   * Process 2nd part of TEK
   */
  /* SPI */
  iec90_5_p2_tek = iec90_5_tek + IEC90_5_TEK_P1_SZ + iec_proto->oid_sz;
  proto->spi_sz[0] = 1; /* Hard code to match TEK */
  proto->spi[0] = malloc(proto->spi_sz[0]);
  if (!proto->spi[0])
	{
	  log_error ("gdoi_iec90_5_decode_tek: malloc failure -- SPI (%d bytes)",
			  	 proto->spi_sz[0]);
	  goto clean_up;
	}
  *proto->spi[0] = GET_IEC90_5_TEK_P2_CUR_KEY_ID(iec90_5_p2_tek);
  log_print(" SPI found (SA) %u (%01#x) for sa %#x", 
		    *proto->spi[0], *proto->spi[0], sa);

  /* Lifetime & Reserved byte */
  tmp_1byte = GET_IEC90_5_TEK_P2_LT_ID(iec90_5_p2_tek);
  if (1 != tmp_1byte) {
      log_print ("gdoi_iec90_5_decode_tek: Wrong LT ID %d\n", tmp_1byte);
      goto clean_up;
  }
  tmp_1byte = GET_IEC90_5_TEK_P2_RES(iec90_5_p2_tek);
  if (0 != tmp_1byte) {
      log_print ("gdoi_iec90_5_decode_tek: Wrong Reserved byte value %d\n", 
			     tmp_1byte);
      goto clean_up;
  }
  tmp_1byte = GET_IEC90_5_TEK_P2_LT_V(iec90_5_p2_tek);
  if (1 != tmp_1byte) {
      log_print ("gdoi_iec90_5_decode_tek: Wrong LT V %d\n", tmp_1byte);
      goto clean_up;
  }
  iec_proto->lifetime_secs = GET_IEC90_5_TEK_P2_LT(iec90_5_p2_tek);

  /* Authentication values */
  tmp_1byte = GET_IEC90_5_TEK_P2_AUTH_ALG_ID(iec90_5_p2_tek);
  if (5 != tmp_1byte) {
      log_print ("gdoi_iec90_5_decode_tek: Wrong Auth value  %d\n", tmp_1byte);
      goto clean_up;
  }
  iec_proto->auth_alg = GET_IEC90_5_TEK_P2_AUTH_ALG(iec90_5_p2_tek);
  iec_proto->auth_key_size = GET_IEC90_5_TEK_P2_KEY_LEN(iec90_5_p2_tek);

  return 0;
 
clean_up:
  if (proto)
    {
  	  proto_free(proto);
	}
  return -1;
}
      
/*
 * Translate keys from the IEC90-5 proto into a generic structure
 */
int
gdoi_iec90_5_get_tek_keys (struct gdoi_kd_decode_arg *keys, struct proto *proto)
{
 struct iec90_5_proto *iec_proto= (struct iec90_5_proto *) proto->data;
 u_int8_t *kd_buf;
 u_int32_t kd_sz;

  /*
   * Build a private KD attribute for IEC90-5.
   */
  if (!iec_proto->auth_key_size) {
	  log_print ("gdoi_iec90_5_get_tek_keys: Warning: No keys to send!");
	  return 0;
  }


  kd_sz = IEC90_5_KD_SZ + iec_proto->auth_key_size;
  kd_buf = calloc(1, kd_sz);
  if (!kd_buf) {
	  log_print ("gdoi_iec90_5_get_tek_keys: Failed to get %d bytes for "
			     "IEC90-5 KD payload", kd_sz);
	  return -1;
  }

  /*
   * Note: Most or all of these hard coded values should have come from policy 
   * stored in iec_proto.
   */
  SET_IEC90_5_KD_LT_ID(kd_buf,1);
  SET_IEC90_5_KD_LT_V(kd_buf,1);
  SET_IEC90_5_KD_RES(kd_buf,0);
  SET_IEC90_5_KD_LT(kd_buf, 3600);
  SET_IEC90_5_KD_AUTH_ALG_ID(kd_buf, 5);
  SET_IEC90_5_KD_AUTH_ALG(kd_buf, 2);
  SET_IEC90_5_KD_KEY_LEN(kd_buf, iec_proto->auth_key_size);
  memcpy(kd_buf + IEC90_5_KD_SZ, iec_proto->auth_key, iec_proto->auth_key_size);

  keys->custom_kd_payload = kd_buf;
  keys->custom_kd_payload_sz = kd_sz;
  /* I have not idea which value to use for the payload type */
  keys->custom_kd_payload_type = IEC90_5_KD_61850_ETHERENT_GOOSE_OR_SV; 
 
  return 0;
}

/*
 * Group member side
 * Validate and install keys gotten from the KD in the iec_proto structure.
 */
int
gdoi_iec90_5_install_keys (struct proto *proto, struct gdoi_kd_decode_arg *keys)
{
  struct iec90_5_proto *iec_proto;
  u_int8_t *kd_buf;

  kd_buf = keys->custom_kd_payload;

  if (proto->proto != IPSEC_PROTO_IEC90_5)
    {
      log_error ("gdoi_iec90_5_install_keys: IEC90_5 SA expected, got %d",
	  			 proto->proto);
      return -1;
	}

  iec_proto = (struct iec90_5_proto *) proto->data;
  if (!iec_proto)
    {
      log_error ("gdoi_iec90_5_install_keys: IEC90_5 SA TEK data missing");
      return -1;
    }

  if (GET_IEC90_5_KD_KEY_LEN(kd_buf) != iec_proto->auth_key_size) {
	  log_print ("gdoi_iec90_5_install_keys: Auth key size doesn't match"
			     "key size sent in TEK");
	  return -1;
  }

  iec_proto->auth_key = malloc(iec_proto->auth_key_size);
  if (!iec_proto->auth_key)
	{
	  log_print ("gdoi_iec90_5_get_policy: malloc failed: auth key (%d)",
			  	 iec_proto->auth_key_size);
	  return -1;
	}
  memcpy(iec_proto->auth_key, kd_buf + IEC90_5_KD_SZ, iec_proto->auth_key_size);

  /* No need to save policy already sent in the TEK payload */
  
  return 0;
}

u_int8_t *
gdoi_iec90_5_add_attributes (u_int8_t *attr, struct sa *sa)
{
  struct proto *proto = NULL;
  struct iec90_5_proto *iec_proto = NULL;

  proto = TAILQ_LAST(&sa->protos, proto_head);
  iec_proto = (struct iec90_5_proto *) proto->data;

  attr = attribute_set_var(attr, IEC90_5_OID, iec_proto->oid, 
		  				   iec_proto->oid_sz);
  attr = attribute_set_var(attr, IEC90_5_LIFETIME_SECS, 
		  				   (u_int8_t *)&iec_proto->lifetime_secs, 
						   sizeof(iec_proto->lifetime_secs));
  attr = attribute_set_basic(attr, IEC90_5_KEYID, *proto->spi[0]);
  attr = attribute_set_basic(attr, IEC90_5_AUTH_ALG, iec_proto->auth_alg);
  attr = attribute_set_basic(attr, IEC90_5_AUTH_KEY_SIZE, 
		  					 iec_proto->auth_key_size);

  if (!iec_proto->auth_key) 
    {
  	  log_print ("gdoi_iec90_5_add_attributes: Auth key missing!\n");
	}
  else 
    {
  	  attr = attribute_set_var (attr, IEC90_5_AUTH_KEY, iec_proto->auth_key,
			    				iec_proto->auth_key_size);
    }

  return attr;
}
