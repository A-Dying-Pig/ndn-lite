/*
 * Copyright (C) 2018-2019 Tianyuan Yu, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#include "service-discovery.h"

#ifndef FORWARDER_FORWARDER_H
#include "../forwarder/forwarder.h"
#endif

static ndn_sd_context_t sd_context;
static uint8_t encode_buffer[250];
static uint32_t sd_lifetime;
static ndn_interest_t sd_interest, sd_interest_query;
static ndn_data_t sd_data;

/************************************************************/
/*  Definition of Forwarder Callback Wrapper                */
/************************************************************/
static int
_on_advertisement(const uint8_t* interest, uint32_t interest_size, void* usrdata)
{
  (void)usrdata;
  ndn_interest_from_block(&sd_interest, interest, interest_size);
  ndn_sd_on_advertisement_process(&sd_interest);
  return NDN_FWD_STRATEGY_SUPPRESS;
}

static int
_on_query(const uint8_t* interest, uint32_t interest_size, void* usrdata)
{
  (void)usrdata;
  ndn_interest_from_block(&sd_interest, interest, interest_size);
  ndn_sd_on_query_process(&sd_interest, &sd_data);
  return NDN_FWD_STRATEGY_SUPPRESS;
}

static void
_on_query_response(const uint8_t* data, uint32_t data_size, void* usrdata)
{
  (void)usrdata;
  // TODO: Verify signature before processing
  ndn_data_tlv_decode_no_verify(&sd_data, data, data_size);
  ndn_sd_on_query_process(&sd_data);
}

static void
_on_advertisement_timeout(void* usrdata)
{
  ndn_sd_advertisement((uint32_t)(*usrdata));
}

static void
_on_query_timeout(void* usrdata)
{
  ndn_sd_on_query_timeout_process((ndn_interest_t*)usrdata);
}
/************************************************************/
/*  Definition of Neighbors APIS                            */
/************************************************************/

static void
_neighbors_init(void)
{
  for (uint8_t i = 0; i < NDN_APPSUPPORT_NEIGHBORS_SIZE; ++i) {
    sd_context.neighbors[i].identity.size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
    for (uint8_t j = 0; j < NDN_APPSUPPORT_SERVICES_SIZE; ++j) {
      sd_context.neighbors[i].services[j].status = NDN_APPSUPPORT_SERVICE_UNDEFINED;
    }
  }
}

static ndn_sd_identity_t*
_neighbors_find_neighbor(const name_component_t* identity)
{
  for (uint8_t i = 0; i < NDN_APPSUPPORT_NEIGHBORS_SIZE; ++i) {
    if (sd_context.neighbors[i].identity.size == NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
      continue;
    }
    if (name_component_compare(&sd_context.neighbors[i].identity, identity) == 0) {
      return &sd_context.neighbors[i];
    }
  }
  return NULL;
}

static ndn_sd_identity_t*
_neighbors_add_neighbor(const name_component_t* identity)
{
  ndn_sd_identity_t* neighbor = _neighbors_find_neighbor(identity);
  if (neighbor != NULL)
    return neighbor;

  for (uint8_t i = 0; i < NDN_APPSUPPORT_NEIGHBORS_SIZE; ++i) {
    if (sd_context.neighbors[i].identity.size == NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
      sd_context.neighbors[i].identity = *identity;
      return &sd_context.neighbors[i];
    }
  }
  return NULL;
}

static int
_neighbor_add_update_service(ndn_sd_identity_t* neighbor,
                             const uint8_t* id_value, uint32_t id_size,
                             const uint8_t status)
{
  for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; ++i) {
    if (neighbor->services[i].status == NDN_APPSUPPORT_SERVICE_UNDEFINED)
      continue;
    if (memcmp(neighbor->services[i].id_value, id_value,
               neighbor->services[i].id_size > id_size?
               id_size : neighbor->services[i].id_size) == 0) {
      neighbor->services[i].status = status;
      return 0;
    }
  }
  for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; ++i) {
    if (neighbor->services[i].status == NDN_APPSUPPORT_SERVICE_UNDEFINED) {
      memcpy(neighbor->services[i].id_value, id_value, id_size);
      neighbor->services[i].id_size = id_size;
      neighbor->services[i].status = status;
      return 0;
    }
  }
  return NDN_OVERSIZE;
}

// invoked when trying to find a service provider
static ndn_sd_identity_t*
_neighbors_find_first_service_provider(const uint8_t* id_value, uint32_t id_size)
{
  for (uint8_t i = 0; i < NDN_APPSUPPORT_NEIGHBORS_SIZE; ++i) {
    if (sd_context.neighbors[i].identity.size == NDN_FWD_INVALID_NAME_COMPONENT_SIZE)
      continue;
    for (uint8_t j = 0; j < NDN_APPSUPPORT_NEIGHBORS_SIZE; ++j) {
      if (memcmp(sd_context.neighbors[i].services[j].id_value, id_value,
                 sd_context.neighbors[i].services[i].id_size > id_size?
                 id_size : sd_context.neighbors[i].services[i].id_size) == 0) {
        return &sd_context.neighbors[i];
      }
    }
  }
  return NULL;
}

// invoked when receiving new advertisement from a neighbor
static void
_neighbor_reset_service(ndn_sd_identity_t* neighbor)
{
  for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; ++i) {
    neighbor->services[i].status = NDN_APPSUPPORT_SERVICE_UNDEFINED;
  }
}

// invoked when the neighbor is not available
static void
_neighbors_remove_neighbor(const name_component_t* id)
{
  ndn_sd_identity_t* neighbor = _neighbors_find_neighbor(id);
  if (neighbor != NULL) {
    neighbor->identity.size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
    _neighbor_reset_service(neighbor);
  }
}

 /************************************************************/
 /*  Definition of service discovery APIs                    */
 /************************************************************/

void
ndn_sd_init(const ndn_name_t* home_prefix, const name_component_t* self_id,
            ndn_ecc_pub_t* pub_key, ndn_ecc_prv_t* prv_key)
{
  _neighbors_init();
  sd_context.self.identity = *self_id;
  sd_context.home_prefix = *home_prefix;
  sd_context.pub_key = *pub_key;
  sd_context.prv_key = *prv_key;

  for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; i++) {
    sd_context.self.services[i].status = NDN_APPSUPPORT_SERVICE_UNDEFINED;
  }

  // Register Advertisement Prefix
  ndn_interest_from_name(&sd_interest, &sd_context.home_prefix);
  name_component_t comp_sd;
  const char* str_sd = "SD-ADV";
  name_component_from_string(&comp_sd, str_sd, strlen(str_sd));
  ndn_name_append_component(&sd_interest->name, &comp_sd);

  ndn_encoder_t encoder;
  encoder_init(&encoder, encode_buffer, sizeof(encode_buffer));
  ndn_name_tlv_encode(&encoder, &sd_interest.name);
  ndn_forwarder_register_prefix(encode_buffer, encoder.offset,
                                _on_advertisement, NULL);

  // Register Query Prefix
  ndn_interest_from_name(&sd_interest, &sd_context.home_prefix);
  const char* str_sd_query1 = "SD";
  name_component_from_string(&comp_sd, str_sd_query1, strlen(str_sd_query1));
  ndn_name_append_component(&sd_interest->name, &comp_sd);
  ndn_name_append_component(&sd_interest->name, &sd_context.self.identity);
  const char* str_sd_query2 = "QUERY";
  name_component_from_string(&comp_sd, str_sd_query2, strlen(str_sd_query2));
  ndn_name_append_component(&sd_interest->name, &comp_sd);

  encoder_init(&encoder, encode_buffer, sizeof(encode_buffer));
  ndn_name_tlv_encode(&encoder, &sd_interest.name);
  ndn_forwarder_register_prefix(encode_buffer, encoder.offset,
                                _on_query, NULL);
}

ndn_service_t*
ndn_sd_register_get_self_service(const char* prefix, uint32_t size)
{
  for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; ++i) {
    if (sd_context.self.services[i].status == NDN_APPSUPPORT_SERVICE_UNDEFINED)
      continue;
    if (memcmp(sd_context.self.services[i].id_value, prefix,
               sd_context.self.services[i].id_size > size?
               size : sd_context.self.services[i].id_size) == 0)
      return &sd_context.self.services[i];
  }
  for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; ++i) {
    if (sd_context.self.services[i].status != NDN_APPSUPPORT_SERVICE_UNDEFINED)
      continue;
    sd_context.self.services[i].status = NDN_APPSUPPORT_SERVICE_AVAILABLE;
    memcpy(&sd_context.self.services[i].id_value, prefix, size);
    sd_context.self.services[i].id_size = size;
    return &sd_context.self.services[i];
  }
  return NULL;
}

ndn_sd_identity_t*
ndn_sd_find_neigbor(const name_component_t* id)
{
  return _neighbors_find_neighbor(id);
}

ndn_sd_identity_t*
ndn_sd_find_first_service_provider(const char* id_value, uint32_t id_size)
{
  return _neighbors_find_first_service_provider((uint8_t*)id_value, id_size);
}

void
ndn_sd_advertisement(uint32_t lifetime)
{
  // make service list and prepare the interest
  ndn_interest_from_name(&sd_interest, &sd_context.home_prefix);

  name_component_t comp_sd;
  const char* str_sd = "SD-ADV";
  name_component_from_string(&comp_sd, str_sd, strlen(str_sd));
  ndn_name_append_component(&sd_interest.name, &comp_sd);
  ndn_name_append_component(&sd_interest.name, &sd_context.self.identity);

  ndn_encoder_t encoder;
  encoder_init(&encoder, &sd_interest.parameters.value, NDN_INTEREST_PARAMS_BUFFER_SIZE);
  for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; i++) {
    if (sd_context.self.services[i].status != NDN_APPSUPPORT_SERVICE_UNDEFINED
        && sd_context.self.services[i].status != NDN_APPSUPPORT_SERVICE_UNAVAILABLE) {
      name_component_t toEncode;
      name_component_from_buffer(&toEncode, TLV_GenericNameComponent,
                                 sd_context.self.services[i].id_value,
                                 sd_context.self.services[i].id_size);
      name_component_tlv_encode(&encoder, &toEncode);
    }
  }
  sd_interest.enable_Parameters = 1;
  sd_interest.parameters.size = encoder.offset;
  sd_interest.lifetime = lifetime;
  sd_lifetime = lifetime;

  encoder_init(&encoder, encode_buffer, sizeof(encode_buffer));
  ndn_interest_tlv_encode(&encoder, &sd_interest);
  ndn_forwarder_express_interest(encode_buffer, encoder.offset,
                                 NULL, _on_advertisement(),
                                 &sd_lifetime);
}

void
ndn_sd_query(name_component_t* target, ndn_service_t* service,
             const uint8_t* params_value, uint32_t params_size,
             uint32_t lifetime)
{
  ndn_interest_from_name(&sd_interest_query, &sd_context.home_prefix);
  name_component_t comp_sd;
  const char* str_sd = "SD";
  name_component_from_string(&comp_sd, str_sd, strlen(str_sd));
  ndn_name_append_component(&sd_interest_query.name, &comp_sd);
  ndn_name_append_component(&sd_interest_query.name, target);

  name_component_t comp_qr;
  const char* str_qr = "QUERY";
  name_component_from_string(&comp_qr, str_qr, strlen(str_qr));
  ndn_name_append_component(&sd_interest_query.name, &comp_qr);

  name_component_t comp_id;
  name_component_from_buffer(&comp_id, TLV_GenericNameComponent, service->id_value, service->id_size);
  ndn_name_append_component(&sd_interest_query.name, &comp_id);

  if (params_value != NULL && params_size > 0) {
    ndn_interest_set_Parameters(&sd_interest_query, params_value, params_size);
  }

  // Signing and Expressing
  ndn_interest_from_name(&sd_interest, &sd_context.home_prefix);
  ndn_name_append_component(&sd_interest.name, &sd_context.self.identity);
  sd_interest_query.lifetime = lifetime;
  ndn_signed_interest_ecdsa_sign(&sd_interest_query, &sd_interest.name,
                                 &sd_context.prv_key);
  ndn_encoder_t encoder;
  encoder_init(&encoder, encode_buffer, sizeof(encode_buffer));
  ndn_interest_tlv_encode(&encoder, &sd_interest_query);
  ndn_forwarder_express_interest(encode_buffer, encoder.offset,
                                 _on_query_response, _on_query_timeout,
                                 &sd_interest_query);
}

int
ndn_sd_on_advertisement_process(const ndn_interest_t* interest)
{
  uint32_t home_len = sd_context.home_prefix.components_size;

  // check and add neighbor
  ndn_sd_identity_t* entry = _neighbors_add_neighbor(&interest->name.components[home_len + 1]);
  if (!entry){
    return NDN_OVERSIZE;
  }

  // reset services
  _neighbor_reset_service(entry);
  ndn_decoder_t decoder;
  decoder_init(&decoder, interest->parameters.value, interest->parameters.size);
  name_component_t toDecode;
  for (; decoder.input_size - decoder.offset > 0;) {
    name_component_tlv_decode(&decoder, &toDecode);
    _neighbor_add_update_service(entry, toDecode.value, toDecode.size,
                                 NDN_APPSUPPORT_SERVICE_AVAILABLE);
  }
  return 0;
}

int
ndn_sd_on_query_process(const ndn_interest_t* interest, ndn_data_t* response)
{
  uint32_t home_len = sd_context.home_prefix.components_size;
  ndn_service_t* entry = NULL;
  for (uint8_t i = 0; i < NDN_APPSUPPORT_SERVICES_SIZE; i++) {
    if (sd_context.self.services[i].status != NDN_APPSUPPORT_SERVICE_UNDEFINED) {
      int r = memcmp(sd_context.self.services[i].id_value, interest->name.components[home_len + 3].value,
                     sd_context.self.services[i].id_size > interest->name.components[home_len + 3].size?
                     interest->name.components[home_len + 3].size : sd_context.self.services[i].id_size);
      if (r == 0) {
        entry = &sd_context.self.services[i];
        break;
      }
    }
  }

  if (entry) {
    uint8_t buffer[3];
    ndn_encoder_t encoder;
    encoder_init(&encoder, buffer, sizeof(buffer));
    encoder_append_type(&encoder, TLV_SD_STATUS);
    encoder_append_length(&encoder, 1);
    encoder_append_byte_value(&encoder, entry->status);

    // (Optional) ECDH_Pub_Key

    response->name = interest->name;
    ndn_data_set_content(response, buffer, sizeof(buffer));

    encoder_init(&encoder, encode_buffer, sizeof(encode_buffer));
    ndn_interest_from_name(&sd_interest, &sd_context.home_prefix);
    ndn_name_append_component(&sd_interest.name, &sd_context.self.identity);
    ndn_data_tlv_encode_ecdsa_sign(&encoder, response, &sd_interest.name,
                                   &sd_context.self.identity);
    ndn_forwarder_put_data(encode_buffer, encoded.offset);
    return 0;
  }
  return NDN_SD_NO_MATCH_SERVCE;
}

int
ndn_sd_on_query_response_process(const ndn_data_t* response)
{
  uint32_t home_len = sd_context.home_prefix.components_size;
  ndn_decoder_t decoder;
  decoder_init(&decoder, response->content_value, response->content_size);
  uint32_t probe;
  uint8_t status;
  decoder_get_type(&decoder, &probe);
  decoder_get_length(&decoder, &probe);
  decoder_get_byte_value(&decoder, &status);

  // try to find the neighbor (add if neighbor got deleted)
  ndn_sd_identity_t* neighbor = _neighbors_add_neighbor(&response->name.components[home_len + 1]);

  // update service status
  _neighbor_add_update_service(neighbor, response->name.components[home_len + 3].value,
                               response->name.components[home_len + 3].size, status);

  // (Optional) ECDH bits
  return 0;
}

int
ndn_sd_on_query_timeout_process(const ndn_interest_t* interest)
{
  uint32_t home_len = sd_context.home_prefix.components_size;
  _neighbors_remove_neighbor(&interest->name.components[home_len + 1]);
  return 0;
}
