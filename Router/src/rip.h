#pragma once

#include <stdint.h>
#define RIP_MAX_ENTRY 25
typedef struct {
  // all fields are big endian
  // we don't store 'family', as it is always 2(response) and 0(request)
  // we don't store 'tag', as it is always 0
  uint32_t addr;
  uint32_t mask;
  uint32_t nexthop;
  uint32_t metric;
} RipEntry;

typedef struct {
  uint32_t numEntries;
  // all fields below are big endian
  uint8_t command;
  // we don't store 'version', as it is always 2
  // we don't store 'zero', as it is always 0
  RipEntry entries[RIP_MAX_ENTRY];
} RipPacket;

#define RIP_VERSION 0x02
#define RIP_REQUEST_COMMAND 0x01
#define RIP_RESPONSE_COMMAND 0x02
#define RIP_REQUEST_FAMILY_ID 0x00
#define RIP_RESPONSE_FAMILY_ID 0x02
#define RIP_TAG 0x00
