#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <algorithm>
using namespace std;

static const in_addr_t MULTICAST_ADDR = 0x090000e0;

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0xef002a0a, 0x01012a0a, 0x0202010a, 0x0103010a};

void printMAC(const macaddr_t mac)
{
  printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void printAddr(in_addr_t addr)
{
  printf("%d.%d.%d.%d", addr & 0xff, (addr >> 8) & 0xff, (addr >> 16) & 0xff, addr >> 24);
}

static inline void sprintAddr(in_addr_t addr, char *buffer)
{
  sprintf(buffer, "%d.%d.%d.%d", addr & 0xff, (addr >> 8) & 0xff, (addr >> 16) & 0xff, addr >> 24);
}

inline bool isMyAddr(in_addr_t addr)
{
  for (int i = 0; i < N_IFACE_ON_BOARD; i++)
  {
    if (addr == addrs[i])
    {
      return true;
    }
  }
  return false;
}

void assembleUdp(uint8_t *buffer, size_t udp_len)
{
  buffer[0] = 0x02; // src port is 520
  buffer[1] = 0x08;
  buffer[2] = 0x02; // dst port is 520
  buffer[3] = 0x08;
  write16Little(buffer + 4, udp_len); // length
}

void assembleIp(uint8_t *buffer, size_t ip_len, in_addr_t src_addr, in_addr_t dst_addr)
{
  buffer[0] = 0x45;                  // version & header len
  buffer[1] = 0xc0;                  // Differentiated Services Field: 0xc0 (DSCP: CS6, ECN: Not-ECT)
  write16Little(buffer + 2, ip_len); // length
  buffer[6] = 0x40;                  // flags
  buffer[8] = 0x01;                  // ttl
  buffer[9] = 0x11;                  // protocal: udp
  write32Big(buffer + 12, src_addr); // src addr
  write32Big(buffer + 16, dst_addr); // dst addr
  auto checksum = Router::computeIPChecksum(buffer, 20);
  write16Little(buffer + 10, checksum);
}

void handleRipResponse(const uint8_t *buffer, const RipPacket &rip, int if_index, in_addr_t src_addr)
{
  // port must be 520
  if (!(buffer[20] == 0x02 && buffer[21] == 0x08 && buffer[22] == 0x02 && buffer[23] == 0x08))
  {
    cout << "invalid reponse: invalid port" << endl;
    return;
  }
  // source addr cannot be mine
  if (isMyAddr(src_addr))
  {
    cout << "invalid reponse: source addr is my addr" << endl;
    return;
  }

  // update routing table
  for (int i = 0; i < rip.numEntries; i++)
  {
    auto respEntry = rip.entries[i];
    if (isMyAddr(respEntry.nexthop))
    {
      // split horizon
      continue;
    }

    // precise match
    auto result = std::find_if(Router::routing_table.begin(), Router::routing_table.end(), [=](const RoutingTableEntry &elem) {
      return elem.addr == respEntry.addr && elem.len == mask2len(respEntry.mask);
    });

    if (result != Router::routing_table.end())
    {
      // found
      auto myEntry = *result;
      if (__bswap_32(respEntry.metric) > 15 && myEntry.nexthop == src_addr)
      {
        // unreachable via src_addr. drop this entry.
        Router::update(false, myEntry);
      }
      if (__bswap_32(respEntry.metric) + 1 < __bswap_32(myEntry.metric))
      {
        myEntry.metric = __bswap_32(__bswap_32(respEntry.metric) + 1);
        Router::update(true, myEntry);
      }
    }
    else
    {
      RoutingTableEntry newEntry;
      newEntry.metric = __bswap_32(__bswap_32(respEntry.metric) + 1);
      if (__bswap_32(newEntry.metric) < 16)
      {
        newEntry.addr = respEntry.addr;
        newEntry.len = mask2len(respEntry.mask);
        newEntry.if_index = if_index;
        newEntry.nexthop = src_addr;

        Router::update(true, newEntry);
      }
    }
  }
}

void sendRoutingTable(int if_index, in_addr_t src_addr, in_addr_t dst_addr, macaddr_t dst_mac)
{
  RipPacket resp;
  resp.numEntries = 0;
  resp.command = RIP_RESPONSE_COMMAND;

  // split horizon
  for (auto &tableEntry : Router::routing_table)
  {
    if (if_index == tableEntry.if_index)
    {
      continue;
    }
    resp.entries[resp.numEntries++] = {
        .addr = tableEntry.addr,
        .mask = len2mask(tableEntry.len),
        .nexthop = tableEntry.nexthop,
        .metric = tableEntry.metric};
  }
  // assemble
  memset(output, 0, sizeof(output));
  // rip
  uint32_t rip_len = Router::assemble(&resp, &output[20 + 8]);
  // udp
  assembleUdp(output + 20, 8 + rip_len);
  // ip
  assembleIp(output, 20 + 8 + rip_len, src_addr, dst_addr);
  // send
  HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, dst_mac);
}

int main(int argc, char *argv[])
{
  // 0a.
  int res = HAL_Init(1, addrs);

  if (res < 0)
  {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++)
  {
    RoutingTableEntry entry = {
        .addr = addrs[i] & 0x00ffffff, // big endian
        .len = 24,                     // small endian
        .if_index = i,                 // small endian
        .nexthop = 0,                  // big endian, means direct
        .metric = 0x01000000};
    Router::update(true, entry);
  }

  uint64_t last_time = 0;

  macaddr_t MULTICAST_MAC; // multicase MAC
  HAL_ArpGetMacAddress(0, MULTICAST_ADDR, MULTICAST_MAC);

  while (1)
  {
    uint64_t time = HAL_GetTicks();

    if (time > last_time + 5 * 1000)
    {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09

      for (int i = 0; i < N_IFACE_ON_BOARD; i++)
      {
        sendRoutingTable(i, addrs[i], MULTICAST_ADDR, MULTICAST_MAC);
      }

      printf("30s Timer\n");
      last_time = time;

      printf("------------------------------------------------------\n");
      printf("| %18s | %2s | %6s | %15s |\n", "net/len", "if", "metric", "nexthop");
      printf("------------------------------------------------------\n");
      for (auto &entry : Router::routing_table)
      {
        static char addr_str[32];
        static char nexthop_str[32];
        sprintAddr(entry.addr, addr_str);
        sprintAddr(entry.nexthop, nexthop_str);
        printf("| %15s/%2d | %2d | %6d | %15s |\n", addr_str, entry.len, entry.if_index, __bswap_32(entry.metric), nexthop_str);
      }
      printf("------------------------------------------------------\n");
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);

    if (!(-1 < if_index && if_index < N_IFACE_ON_BOARD))
    {
      printf("invalid if_index %d", if_index);
      continue;
    }

    if (res == HAL_ERR_EOF)
    {
      break;
    }
    else if (res < 0)
    {
      return res;
    }
    else if (res == 0)
    {
      // Timeout
      continue;
    }
    else if (res > sizeof(packet))
    {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!Router::validateIPChecksum(packet, res))
    {
      printf("Invalid IP Checksum\n");
      continue;
    }

    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr = read32Big(packet + 12);
    dst_addr = read32Big(packet + 16);

    // 2. check whether dst is me
    bool dst_is_me = false;

    for (int i = 0; i < N_IFACE_ON_BOARD; i++)
    {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0)
      {
        dst_is_me = true;
        break;
      }
    }

    // TODO: Handle rip multicast address(224.0.0.9)?
    if (dst_addr == MULTICAST_ADDR)
    {
      RipPacket rip;
      if (Router::disassemble(packet, res, &rip))
      {
        if (rip.command == RIP_REQUEST_COMMAND)
        {
          if (rip.numEntries == 1 && __bswap_32(rip.entries[0].metric) == 16)
          {
            sendRoutingTable(if_index, addrs[if_index], src_addr, src_mac);
          }
        }
        else
        {
          handleRipResponse(packet, rip, if_index, src_addr);
        }
      }
    }
    else if (dst_is_me)
    {
      // 3a.1
      RipPacket rip;

      // check and validate
      if (Router::disassemble(packet, res, &rip))
      {
        if (rip.command == RIP_REQUEST_COMMAND)
        {
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          if (rip.numEntries == 1 && __bswap_32(rip.entries[0].metric) == 16)
          {
            sendRoutingTable(if_index, dst_addr, src_addr, src_mac);
          }
        }
        else
        {
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
          handleRipResponse(packet, rip, if_index, src_addr);
        }
      }
    }
    else
    {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop, dest_if, metric;

      if (Router::query(dst_addr, &nexthop, &dest_if, &metric))
      {
        // found
        macaddr_t dest_mac;

        // direct routing
        if (nexthop == 0)
        {
          nexthop = dst_addr;
        }

        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0)
        {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          Router::forward(output, res);

          // TODO: you might want to check ttl=0 case
          if (output[8] == 0)
          {
            // ttl is 0
            cout << "ttl is 0, drop packet" << endl;
            continue;
          }

          HAL_SendIPPacket(dest_if, output, res, dest_mac);
        }
        else
        {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      }
      else
      {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }

  return 0;
}
