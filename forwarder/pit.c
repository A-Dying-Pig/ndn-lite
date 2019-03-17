/*
 * Copyright (C) 2018-2019 Zhiyi Zhang, Xinyu Ma
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 */

#include "pit.h"

static inline void
ndn_pit_entry_reset(ndn_pit_entry_t* self){
  self->nametree_id = NDN_INVALID_ID;
  self->last_time = 0;
  self->express_time = 0;
  self->incoming_faces = 0;
  self->on_data = NULL;
  self->on_timeout = NULL;
  self->userdata = NULL;
}

void
ndn_pit_init(void* memory, uint16_t capacity, ndn_nametree_t* nametree){
  uint16_t i;
  ndn_pit_t* self = (ndn_pit_t*)memory;
  self->capacity = capacity;
  self->nametree = nametree;
  for(i = 0; i < capacity; i ++){
    ndn_pit_entry_reset(&self->slots[i]);
  }
}

static inline void
ndn_pit_remove_entry(ndn_pit_t* self, uint16_t index){
  (*self->nametree)[self->slots[index].nametree_id].fib_id = NDN_INVALID_ID;
  ndn_pit_entry_reset(&self->slots[index]);
}

static inline void
ndn_pit_remove_entry_if_empty(ndn_pit_t* self, uint16_t index){
  if(self->slots[index].incoming_faces == 0 &&
     self->slots[index].on_data == NULL &&
     self->slots[index].on_timeout == NULL)
  {
    ndn_pit_remove_entry(self, index);
  }
}

void
ndn_pit_unregister_face(ndn_pit_t* self, uint16_t face_id){
  for (uint16_t i = 0; i < self->capacity; ++i){
    self->slots[i].incoming_faces = bitset_unset(self->slots[i].incoming_faces, face_id);
    ndn_pit_remove_entry_if_empty(self, i);
  }
}

int ndn_pit_add_new_entry(ndn_pit_t* pit , int offset)
{
  for (uint16_t i = 0; i < pit -> capacity; ++i)
    if (pit -> slots[i].nametree_id == NDN_INVALID_ID) {
      ndn_pit_refresh_entry(pit -> slots[i]);
      pit -> slots[i].nametree_id = offset;
      return i;
    }
  return NDN_INVALID_ID;
}

ndn_pit_entry_t*
ndn_pit_find_or_insert(ndn_pit_t* self, uint8_t* prefix, size_t length){
  nametree_entry_t* entry = ndn_nametree_find_or_insert(self->nametree, prefix, length);
  if(entry == NULL){
    return NULL;
  }
  if(entry->pit_id == NDN_INVALID_ID){
    entry->pit_id = ndn_pit_add_new_entry(self, entry - &(*self->nametree)[0]);
    if(entry->pit_id == NDN_INVALID_ID){
      return NULL;
    }
  }
  return &self->slots[entry->pit_id];
}