#include <stdint.h>
#include <stdlib.h>
#include "router.h"

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool Router::forward(uint8_t *packet, size_t len)
{
  if (!validateIPChecksum(packet, len))
  {
    return false;
  }

  packet[8] -= 1;

  size_t header_len = (packet[0] & 0x0f) * 4;

  uint16_t checksum = computeIPChecksum(packet, header_len);

  packet[10] = checksum >> 8;
  packet[11] = checksum & 0xff;

  return true;
}
