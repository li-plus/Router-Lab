#include <stdint.h>
#include <stdlib.h>


uint16_t computeIPChecksum(const uint8_t *packet, size_t header_len)
{
  uint16_t given_checksum = (packet[10] << 8) | packet[11];

  uint32_t checksum = 0;

  int i;
  for (i = 0; i < header_len; i += 2)
  {
    checksum += (packet[i] << 8) | packet[i + 1];
  }

  if (i < header_len)
  {
    checksum += packet[i];
  }

  checksum -= given_checksum;

  while (checksum >> 16)
  {
    checksum = (checksum >> 16) + (checksum & 0xffff);
  }

  return (uint16_t)~checksum;
}

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len)
{
  if (len < 1)
  {
    return false;
  }

  size_t header_len = (packet[0] & 0x0f) * 4;

  if (len < header_len)
  {
    return false;
  }

  uint16_t given_checksum = (packet[10] << 8) | packet[11];

  bool result = (computeIPChecksum(packet, header_len) == given_checksum);

  return result;
}

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len)
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
