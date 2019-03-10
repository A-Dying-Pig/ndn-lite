/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef FORWARDER_PIT_H_
#define FORWARDER_PIT_H_

#include "../encode/interest.h"
#include "../util/timer.h"
#include "face.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ndn_pit_entry is a class of PIT entries.
 */
typedef struct ndn_pit_entry {
  /**
   * The name of representative Interest.
   * A name with components_size < 0 indicates an empty entry.
   */
  ndn_buffer_t interest_buffer;

  /**
   * Collection of incoming faces.
   */
  ndn_face_intf_t* incoming_face[NDN_MAX_FACE_PER_PIT_ENTRY];

  /**
   * The count of incoming faces.
   */
  uint8_t incoming_face_size;

  /**
   * @todo How to timeout?
   */
   ndn_timer_t timer;
} ndn_pit_entry_t;

/**
 * The class of pending Interest table (PIT).
 */
typedef ndn_pit_entry_t ndn_pit_t[NDN_PIT_MAX_SIZE];

/**
 * Add an incoming face to a PIT entry.
 * @param entry. Input. The PIT entry.
 * @param face. Input. The incoming face.
 * @return 0 if there is no error.
 */
int
pit_entry_add_incoming_face(ndn_pit_entry_t* entry, ndn_face_intf_t* face);

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_PIT_H
