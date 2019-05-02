/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "service-discovery.h"
#include "service-discovery-helpers.h"
#ifndef FORWARDER_FORWARDER_H
#include "../forwarder/forwarder.h"
#endif

#include "stdio.h"

static ndn_sd_buffer_t sd_buffer;

/************************************************************/
/*  Definition of Forwarder Callback Wrapper                */
/************************************************************/
static int
_on_advertisement(const uint8_t* interest, uint32_t interest_size, void* usrdata)
{
  (void)usrdata;
  ndn_interest_from_block(&sd_buffer.interest, interest, interest_size);
  ndn_sd_on_advertisement_process(&sd_buffer.interest);
  return NDN_FWD_STRATEGY_SUPPRESS;
}

static int
_on_query(const uint8_t* interest, uint32_t interest_size, void* usrdata)
{
  (void)usrdata;
  ndn_interest_from_block(&sd_buffer.interest, interest, interest_size);
  int ret = ndn_sd_on_query_process(&sd_buffer.data, &sd_buffer.data);
  if (ret == 0)
  {
    sd_buffer.identity = sd_context.home_prefix;
    ndn_name_append_component(&sd_buffer.identity, sd_context.self_id);
    ndn_encoder_t encoder;
    encoder_init(&encoder, sd_buffer.encode_buffer, sizeof(sd_buffer.encode_buffer));
    ndn_data_tlv_encode_ecdsa_sign(&encoder, &sd_buffer.data,
                                   &sd_buffer.identity, &sd_buffer.prv_key);
    ret = ndn_forwarder_put_data(sd_buffer.encode_buffer, encoder.offset);
    if (ret)
      printf("query put data failure\n");

  }
  return NDN_FWD_STRATEGY_SUPPRESS;
}

static void
_on_query_response(const uint8_t* data, uint32_t data_size, void* usrdata)
{
  (void)usrdata;
  // TODO: verify signature before processing
  ndn_data_tlv_decode_no_verify(&sd_data, data, data_size);
  ndn_sd_on_query_process(&sd_data);
}

void
_re_advertisement(void* ptr)
{
  uint32_t* adv_lifetime = (uint32_t*)ptr;
  ndn_sd_advertisement(*adv_lifetime);
}

 /************************************************************/
 /*  Definition of service discovery APIs                    */
 /************************************************************/
 void
 ndn_sd_register(const ndn_name_t* home_prefix, const name_component_t* self_id,
                 ndn_ecc_pub_t* pub_key, ndn_ecc_prv_t* prv_key)
{
  ndn_sd_init(home_prefix, self_id);
  sd_buffer.pub_key = *pub_key;
  sd_buffer.prv_key = *prv_key;

  // reuses buffer's interest name to register SD prefixes
  ndn_interest_from_name(&sd_buffer.interest.name, &sd_context.home_prefix);
  name_component_t comp_sd;
  const char* str_sd = "SD-ADV";
  name_component_from_string(&comp_sd, str_sd, strlen(str_sd));
  ndn_name_append_component(&sd_buffer.interest.name, &comp_sd);

  ndn_encoder_t encoder;
  encoder_init(&encoder, sd_buffer.encode_buffer, sizeof(sd_buffer.encode_buffer));
  ndn_name_tlv_encode(&encoder, &sd_interest.name);
  ndn_forwarder_register_prefix(sd_buffer.encode_buffer, encoder.offset,
                                _on_advertisement, NULL);

  ndn_interest_from_name(&sd_buffer.interest.name, &sd_context.home_prefix);
  const char* str_sd_query1 = "SD";
  name_component_from_string(&comp_sd, str_sd_query1, strlen(str_sd_query1));
  ndn_name_append_component(&sd_buffer.interest.name, &comp_sd);
  ndn_name_append_component(&sd_buffer.interest.name, &sd_context.self.identity);
  const char* str_sd_query2 = "QUERY";
  name_component_from_string(&comp_sd, str_sd_query2, strlen(str_sd_query2));
  ndn_name_append_component(&sd_buffer.interest.name, &comp_sd);

  encoder_init(&encoder, sd_buffer.encode_buffer, sizeof(sd_buffer.encode_buffer));
  ndn_name_tlv_encode(&encoder, &sd_buffer.interest.name);
  ndn_forwarder_register_prefix(sd_buffer.encode_buffer, encoder.offset,
                                _on_query, NULL);
}


void
ndn_sd_advertisement(uint32_t adv_lifetime)
{
  sd_buffer.adv_lifetime = lifetime;

  // make service list and prepare the interest
  ndn_interest_from_name(&sd_buffer.interest, &sd_context.home_prefix);
  ndn_sd_prepare_advertisement(&sd_buffer.interest);

  ndn_encoder_t encoder;
  encoder_init(&encoder, sd_buffer.encode_buffer, sizeof(sd_buffer.encode_buffer));
  ndn_interest_tlv_encode(&encoder, &sd_buffer.interest);
  ndn_forwarder_express_interest(sd_buffer.encode_buffer, encoder.offset,
                                 NULL, _re_advertisement, &sd_buffer.adv_lifetime);
}

void
ndn_sd_query(name_component_t* target, ndn_service_t* service,
             const uint8_t* params_value, uint32_t params_size,
             uint32_t lifetime)
{
  ndn_sd_prepare_query(&sd_buffer.interest, target, service,
                      params_value, params_size);
  sd_buffer.interest.lifetime = lifetime;

  // Sign and Express
  sd_buffer.identity = sd_context.home_prefix;
  ndn_name_append_component(&sd_buffer.identity, sd_context.self_id);
  ndn_signed_interest_ecdsa_sign(&sd_buffer.interest, &sd_buffer.interest.name,
                                 &sd_buffer.prv_key);
  ndn_encoder_t encoder;
  encoder_init(&encoder, sd_buffer.encode_buffer, sizeof(sd_buffer.encode_buffer));
  ndn_interest_tlv_encode(&encoder, &sd_buffer.interest);
  ndn_forwarder_express_interest(sd_buffer.encode_buffer, encoder.offset,
                                 _on_query_response, _on_query_timeout,
                                 NULL);
}
