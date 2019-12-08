#pragma once

#include <stdint.h>
#include <stdio.h>
#include <vector>
#include "rip.h"

// 路由表的一项
typedef struct {
    uint32_t addr; // 地址
    uint32_t len; // 前缀长度
    uint32_t if_index; // 出端口编号
    uint32_t nexthop; // 下一条的地址，0 表示直连
    // 为了实现 RIP 协议，需要在这里添加额外的字段
} RoutingTableEntry;

static std::vector<RoutingTableEntry> routing_table;

bool validateIPChecksum(uint8_t *packet, size_t len);

void update(bool insert, RoutingTableEntry entry);

bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);

bool forward(uint8_t *packet, size_t len);

bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);

uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

uint16_t computeIPChecksum(const uint8_t *packet, size_t header_len);
