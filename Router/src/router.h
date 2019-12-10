#pragma once

#include <stdint.h>
#include <stdio.h>
#include <vector>
#include <stdlib.h>
#include "rip.h"

// 路由表的一项
typedef struct
{
  uint32_t addr;     // 地址
  uint32_t len;      // 前缀长度
  uint32_t if_index; // 出端口编号
  uint32_t nexthop;  // 下一条的地址，0 表示直连
  // 为了实现 RIP 协议，需要在这里添加额外的字段
  uint32_t metric;
} RoutingTableEntry;

class Router
{
public:
  static std::vector<RoutingTableEntry> routing_table;

  static bool validateIPChecksum(uint8_t *packet, size_t len);

  static void update(bool insert, RoutingTableEntry entry);

  static bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric);

  static bool forward(uint8_t *packet, size_t len);

  static bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);

  static uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

  static uint16_t computeIPChecksum(const uint8_t *packet, size_t header_len);
};

static inline uint32_t read32Big(const uint8_t *buffer)
{
  return *(uint32_t *)buffer;
}

static inline size_t write32Big(uint8_t *buffer, uint32_t data)
{
  *(uint32_t *)buffer = data;
  return 4;
}

static inline uint16_t read16Little(const uint8_t *buffer)
{
  return (buffer[0] << 8) | buffer[1];
}

static inline size_t write16Little(uint8_t *buffer, uint16_t data)
{
  buffer[0] = data >> 8;
  buffer[1] = data & 0xff;
  return 2;
}

static inline size_t mask2len(uint32_t mask)
{
  return (mask == 0) ? 0 : 32 - __builtin_clz(mask);
}

static inline uint32_t len2mask(size_t len)
{
  return (len == 0) ? 0 : 0xffffffff >> (32 - len);
}
