#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <cstring>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool Router::disassemble(const uint8_t *packet, uint32_t len, RipPacket *output)
{
  size_t header_len = (packet[0] & 0x0f) * 4;

  const uint16_t total_len = (packet[2] << 8) | packet[3];
  if (total_len > len)
  {
    return false;
  }

  static const size_t udp_header_len = 8;
  static const size_t rip_header_len = 4;
  static const size_t rip_entry_len = 20;

  output->numEntries = (total_len - header_len - udp_header_len - rip_header_len) / rip_entry_len;

  const uint8_t *rip_packet = packet + header_len + udp_header_len;

  output->command = rip_packet[0];
  if (!(output->command == RIP_REQUEST_COMMAND || output->command == RIP_RESPONSE_COMMAND))
  {
    return false;
  }

  if (rip_packet[1] != 2)
  {
    // version must be 2
    return false;
  }

  if ((rip_packet[2] | rip_packet[3]) != 0)
  {
    return false;
  }

  rip_packet += rip_header_len;

  for (size_t i = 0; i < output->numEntries; i++)
  {
    if ((rip_packet[2] | rip_packet[3]) != 0) // tag
    {
      return false;
    }
    if (output->command == RIP_RESPONSE_COMMAND)
    {
      if (!(rip_packet[0] == 0 && rip_packet[1] == 2))
      {
        return false;
      }
    }
    else
    {
      if (!(rip_packet[0] == 0 && rip_packet[1] == 0))
      {
        return false;
      }
    }

    output->entries[i] = *(RipEntry *)(rip_packet + 4);

    if (output->entries[i].mask != 0 && output->entries[i].mask != len2mask(mask2len(output->entries[i].mask)))
    {
      return false;
    }
    if (!(0 < __builtin_bswap32(output->entries[i].metric) && __builtin_bswap32(output->entries[i].metric) < 17))
    {
      return false;
    }
    rip_packet += rip_entry_len;
  }

  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t Router::assemble(const RipPacket *rip, uint8_t *buffer)
{
  uint8_t *writePtr = buffer;
  *writePtr++ = rip->command;
  *writePtr++ = RIP_VERSION;
  *writePtr++ = 0;
  *writePtr++ = 0;

  for (size_t i = 0; i < rip->numEntries; i++)
  {
    *writePtr++ = 0;
    *writePtr++ = (rip->command == RIP_REQUEST_COMMAND) ? RIP_REQUEST_FAMILY_ID : RIP_RESPONSE_FAMILY_ID;
    *writePtr++ = 0; // tag
    *writePtr++ = 0; // tag
    memcpy(writePtr, (uint8_t *)&rip->entries[i], sizeof(RipEntry));
    writePtr += sizeof(RipEntry);
  }
  return writePtr - buffer;
}
