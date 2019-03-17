/*
 * Copyright (C) 2018-2019 Xinyu Ma, Zhiyi Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "forwarder.h"
#include "pit.h"
#include "fib.h"
#include "face-table.h"
#include "../encode/decoder.h"

#define NDN_FORWARDER_RESERVE_SIZE(nametree_size, facetab_size, fib_size, pit_size) \
  (NDN_NAMETREE_RESERVE_SIZE(nametree_size) + \
   NDN_FACE_TABLE_RESERVE_SIZE(facetab_size) + \
   NDN_FIB_RESERVE_SIZE(fib_size) + \
   NDN_PIT_RESERVE_SIZE(pit_size))

#define NDN_FORWARDER_DEFAULT_SIZE \
  NDN_FORWARDER_RESERVE_SIZE(NDN_NAMETREE_MAX_SIZE, \
                             NDN_FACE_TABLE_MAX_SIZE, \
                             NDN_FIB_MAX_SIZE, \
                             NDN_PIT_MAX_SIZE)

/**
 * NDN-Lite forwarder.
 * We will support content support in future versions.
 * The NDN forwarder is a singleton in an application.
 */
typedef struct ndn_forwarder {
  ndn_nametree_t* nametree;
  ndn_face_table_t* facetab;

  /**
   * The forwarding information base (FIB).
   */
  ndn_fib_t* fib;
  /**
   * The pending Interest table (PIT).
   */
  ndn_pit_t* pit;

  uint8_t memory[NDN_FORWARDER_DEFAULT_SIZE];
} ndn_forwarder_t;

static ndn_forwarder_t forwarder;

void
ndn_forwarder_init(void)
{
  uint8_t* ptr = (uint8_t*)forwarder.memory;
  ndn_nametree_init(ptr, NDN_NAMETREE_MAX_SIZE);
  forwarder.nametree = (ndn_nametree_t*)ptr;

  ptr += NDN_NAMETREE_RESERVE_SIZE(NDN_NAMETREE_MAX_SIZE);
  ndn_facetab_init(ptr, NDN_FACE_TABLE_MAX_SIZE);
  forwarder.facetab = (ndn_face_table_t*)ptr;

  ptr += NDN_FACE_TABLE_RESERVE_SIZE(NDN_NAMETREE_MAX_SIZE);
  ndn_fib_init(ptr, NDN_FIB_MAX_SIZE, forwarder.nametree);
  forwarder.fib = (ndn_fib_t*)ptr;

  ptr += NDN_FIB_RESERVE_SIZE(NDN_FIB_MAX_SIZE);
  ndn_pit_init(ptr, NDN_PIT_MAX_SIZE, forwarder.nametree);
  forwarder.pit = (ndn_pit_t*)ptr;
}

int
ndn_forwarder_process(void){
  ndn_msgqueue_process();
}

int
ndn_forwarder_register_face(ndn_face_intf_t* face)
{
  if(face == NULL)
    return NDN_FWD_INVALID_FACE;
  if(face->face_id != NDN_INVALID_ID)
    return NDN_FWD_NO_EFFECT;
  face->face_id = ndn_facetab_register(forwarder.facetab, face);
  if(face->face_id == NDN_INVALID_ID)
    return NDN_FWD_FACE_TABLE_FULL;
  return NDN_SUCCESS;
}

int
ndn_forwarder_unregister_face(ndn_face_intf_t* face)
{
  if(face == NULL)
    return NDN_FWD_INVALID_FACE;
  if(face->face_id == NDN_INVALID_ID)
    return NDN_FWD_NO_EFFECT;
  if(face->face_id >= forwarder.facetab->capacity)
    return NDN_FWD_INVALID_FACE;
  ndn_fib_unregister_face(forwarder.fib, face->face_id);
  ndn_pit_unregister_face(forwarder.pit, face->face_id);
  ndn_facetab_unregister(forwarder.facetab, face->face_id);
  face->face_id = NDN_INVALID_ID;
  return NDN_SUCCESS;
}

static inline int
ndn_forwarder_tlv_check(uint8_t* prefix, size_t length, uint32_t tlv_type){
  // TODO: Delete this function; refactor decoder/encoder
  ndn_decoder_t decoder;
  uint32_t val;
  int ret;

  if(prefix == NULL)
    return NDN_INVALID_POINTER;

  decoder_init(&decoder, prefix, length);
  ret = decoder_get_type(&decoder, &val);
  if(ret != NDN_SUCCESS)
    return ret;
  if(val != tlv_type)
    return NDN_WRONG_TLV_TYPE;

  ret = decoder_get_length(&decoder, &val);
  if(ret != NDN_SUCCESS)
    return ret;
  if(val != length - decoder.offset)
    return NDN_WRONG_TLV_LENGTH;

  return NDN_SUCCESS;
}

int
ndn_forwarder_add_route(ndn_face_intf_t* face, uint8_t* prefix, size_t length)
{
  uint32_t val;
  int ret;
  ndn_fib_entry_t* fib_entry;

  if(face == NULL)
    return NDN_FWD_INVALID_FACE;
  if(face->face_id >= forwarder.facetab->capacity)
    return NDN_FWD_INVALID_FACE;
  ret = ndn_forwarder_tlv_check(prefix, length, TLV_Name);
  if(ret != NDN_SUCCESS)
    return ret;

  fib_entry = ndn_fib_find_or_insert(forwarder.fib, prefix, length);
  if (fib_entry == NULL)
    return NDN_FWD_FIB_FULL;
  fib_entry->nexthop = bitset_set(fib_entry->nexthop, face->face_id);
  return NDN_SUCCESS;
}

int
ndn_forwarder_remove_route(ndn_face_intf_t* face, uint8_t* prefix, size_t length)
{
  int ret;

  if(face == NULL)
    return NDN_FWD_INVALID_FACE;
  if(face->face_id >= forwarder.facetab->capacity)
    return NDN_FWD_INVALID_FACE;
  ret = ndn_forwarder_tlv_check(prefix, length, TLV_Name);
  if(ret != NDN_SUCCESS)
    return ret;

  ndn_fib_entry_t* fib_entry = ndn_fib_find(forwarder.fib, prefix, length);
  if (fib_entry == NULL)
    return NDN_FWD_NO_EFFECT;
  fib_entry->nexthop = bitset_unset(fib_entry->nexthop, face->face_id);
  ndn_fib_remove_entry_if_empty(forwarder.fib, fib_entry - forwarder.fib);
  return NDN_SUCCESS;
}

int
ndn_forwarder_remove_all_routes(uint8_t* prefix, size_t length)
{
  int ret = ndn_forwarder_tlv_check(prefix, length, TLV_Name);
  if(ret != NDN_SUCCESS)
    return ret;

  ndn_fib_entry_t* fib_entry = ndn_fib_find(forwarder.fib, prefix, length);
  if (fib_entry == NULL)
    return NDN_FWD_NO_EFFECT;
  fib_entry->nexthop = 0;
  ndn_fib_remove_entry_if_empty(forwarder.fib, fib_entry - forwarder.fib);
  return NDN_SUCCESS;
}

//receive a packet from face
int
ndn_forwarder_receive(ndn_face_intf_t* face, const uint8_t* packet, size_t length)
{
  //interest?data
  //TODO
}

int
ndn_forwarder_register_prefix(uint8_t* prefix,
                              size_t length,
                              ndn_on_interest_func on_interest,
                              void* userdata)
{
  int ret = ndn_forwarder_tlv_check(prefix, length, TLV_Name);
  if(ret != NDN_SUCCESS)
    return ret;
  if (on_interest == NULL)
    return NDN_INVALID_POINTER;

  ndn_fib_entry_t* fib_entry = ndn_fib_find_or_insert(forwarder.fib, prefix, length);
  if (fib_entry == NULL)
    return NDN_FWD_FIB_FULL;
  fib_entry->on_interest = on_interest;
  fib_entry->userdata = userdata;
  return NDN_SUCCESS;
}

int
ndn_forwarder_unregister_prefix(uint8_t* prefix, size_t length)
{
  int ret = ndn_forwarder_tlv_check(prefix, length, TLV_Name);
  if(ret != NDN_SUCCESS)
    return ret;

  nametree_entry_t* entry = ndn_fib_find(forwarder.nametree, prefix, length);
  if (entry == NULL)
    return NDN_FWD_NO_EFFECT;
  fib_entry->on_interest = NULL;
  fib_entry->userdata = NULL;
  ndn_fib_remove_entry_if_empty(forwarder.fib, fib_entry - forwarder.fib);
  return NDN_SUCCESS;
}

int
ndn_forwarder_express_interest(const uint8_t* interest,
                               size_t length,
                               ndn_on_data_func on_data,
                               ndn_on_timeout_func on_timeout,
                               void* userdata)
{
  int ret = ndn_forwarder_tlv_check(interest, length, TLV_Interest);
  if(ret != NDN_SUCCESS)
    return ret;
  if (on_data == NULL)
    return NDN_INVALID_POINTER;

  ndn_pit_entry_t* pit_entry = ndn_pit_find_or_insert(forwarder.pit, interest, length);
  if (pit_entry == NULL)
    return NDN_FWD_PIT_FULL;
  pit_entry->on_data = on_data;
  pit_entry->on_timeout = on_timeout;
  pit_entry->userdata = userdata;
  return ndn_forwarder_receive(NULL, interest, length);
}

int
ndn_forwarder_put_data(const uint8_t* data, size_t length)
{
  int ret = ndn_forwarder_tlv_check(interest, length, TLV_Data);
  if(ret != NDN_SUCCESS)
    return ret;
  return ndn_forwarder_receive(NULL, data, length);
}
