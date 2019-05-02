/*
 * Copyright (C) 2019 Tianyuan Yu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */
#ifndef NDN_APP_SUPPORT_SERVICE_DISCOVERY_HELPERS_H
#define NDN_APP_SUPPORT_SERVICE_DISCOVERY_HELPERS_H

#define SD_ENCODE_BUFFER_SIZE 300

#include "../encode/interest.h"
#include "../encode/data.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The structure to implement byte buffer in Service Discovery.
 */
typedef struct ndn_sd_buffer {
  /**
   * The buffer used to encode.
   */
  uint8_t encoder_buffer[SD_ENCODE_BUFFER_SIZE];
  /**
   * The buffered interest
   */
  ndn_interest_t interest;

  /**
   * The buffered data
   */
  ndn_data_t data;

  /**
   * The buffered name
   */
  ndn_name_t identity;

  /**
   * The advertisement lifetime.
   */
  uint32_t adv_lifetime;

  /**
   * The identity public key.
   */
  ndn_ecc_pub_t pub_key;

  /**
   * The identity private key.
   */
  ndn_ecc_prv_t prv_key;
} ndn_sd_buffer_t;

/**
 * Init a Service Discovery State structure and register prefix for ADV and QUERY.
 * Wrapper of sd_init() to make SD interact with forwarder.
 * @param home_prefix. Input. The network home prefix to configure the state manager.
 * @param self_id. Input. The local state manager identity.
 * @param pub_key. Input. Public key for this idenity holder.
 * @param prv_key. Input. Private key for this identity holder.
 */
void
ndn_sd_register(const ndn_name_t* home_prefix, const name_component_t* self_id,
                ndn_ecc_pub_t* pub_key, ndn_ecc_prv_t* prv_key);


/**
 * Prepare a Service Discovery Advertisement. This function should be called after setting local services status.
 * @param interest. Output. The prepared advertisement interest.
 */
void
ndn_sd_advertisement(uint32_t lifetime);

/**
 * Prepare a Service Discovery Query. Users should manually sign the output query
 * interest to obtain a valid signed query interest.
 * @param interest. Output. The prepared unsigned query interest.
 * @param target. Input. The query target identity.
 * @param service. Input. The query target service.
 * @param params_value. Input. The query parameter buffer (optional)
 * @param params_size. Input. Size of input buffer (optional)
 */
void
ndn_sd_query(name_component_t* target, ndn_service_t* service,
             const uint8_t* params_value, uint32_t params_size,
             uint32_t lifetime);


#ifdef __cplusplus
}
#endif

#endif // NDN_APP_SUPPORT_SERVICE_DISCOVERY_HELPERS_H
