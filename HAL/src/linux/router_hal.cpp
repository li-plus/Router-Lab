#include "router_hal.h"
#include "router_hal_common.h"
#include <stdio.h>

#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <map>
#include <net/if.h>
#include <net/if_arp.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <utility>

#ifndef HAL_PLATFORM_TESTING
#include "platform/standard.h"
#else
#include "platform/testing.h"
#endif

const int IP_OFFSET = 14;

bool inited = false;
int debugEnabled = 0;
in_addr_t interface_addrs[N_IFACE_ON_BOARD] = {0};
macaddr_t interface_mac[N_IFACE_ON_BOARD] = {0};

pcap_t *pcap_in_handles[N_IFACE_ON_BOARD];
pcap_t *pcap_out_handles[N_IFACE_ON_BOARD];

std::map<std::pair<in_addr_t, int>, macaddr_t> arp_table;
std::map<std::pair<in_addr_t, int>, uint64_t> arp_timer;

extern "C" {
pcap_t *pcap_open_immediately(const char *device, int snaplen, int promisc, int to_ms, char *errbuf)
{
	pcap_t *p;
	int status;

	p = pcap_create(device, errbuf);
	if (p == NULL)
		return (NULL);
	status = pcap_set_snaplen(p, snaplen);
	if (status < 0)
		goto fail;
	status = pcap_set_promisc(p, promisc);
	if (status < 0)
		goto fail;
	status = pcap_set_timeout(p, to_ms);
	if (status < 0)
		goto fail;

  status = pcap_set_immediate_mode(p, 1);
  if (status < 0)
    goto fail; 
	status = pcap_activate(p);
	if (status < 0)
		goto fail;
	return (p);
fail:
	pcap_close(p);
	return (NULL);
}

int HAL_Init(int debug, in_addr_t if_addrs[N_IFACE_ON_BOARD]) {
  if (inited) {
    return 0;
  }
  debugEnabled = debug;

  // find matching interfaces and get their MAC address
  struct ifaddrs *ifaddr, *ifa;
  if (getifaddrs(&ifaddr) < 0) {
    if (debugEnabled) {
      fprintf(stderr, "HAL_Init: getifaddrs failed with %s\n", strerror(errno));
    }
    return HAL_ERR_UNKNOWN;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (ifa->ifa_addr->sa_family == AF_PACKET &&
          strcmp(ifa->ifa_name, interfaces[i]) == 0) {
        // found
        memcpy(interface_mac[i],
               ((struct sockaddr_ll *)ifa->ifa_addr)->sll_addr,
               sizeof(macaddr_t));
        memcpy(arp_table[std::pair<in_addr_t, int>(if_addrs[i], i)],
               interface_mac[i], sizeof(macaddr_t));
        if (debugEnabled) {
          fprintf(stderr, "HAL_Init: found MAC addr of interface %s\n",
                  interfaces[i]);
        }
        break;
      }
    }
  }
  freeifaddrs(ifaddr);

  // init pcap handles
  char error_buffer[PCAP_ERRBUF_SIZE];
  for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
    pcap_in_handles[i] =
        pcap_open_immediately(interfaces[i], BUFSIZ, 1, 1, error_buffer);
    if (pcap_in_handles[i]) {
      pcap_setnonblock(pcap_in_handles[i], 1, error_buffer);
      if (debugEnabled) {
        fprintf(stderr, "HAL_Init: pcap capture enabled for %s\n",
                interfaces[i]);
      }
    } else {
      if (debugEnabled) {
        fprintf(stderr,
                "HAL_Init: pcap capture disabled for %s, either the interface "
                "does not exist or permission is denied\n",
                interfaces[i]);
      }
    }
    pcap_out_handles[i] =
        pcap_open_immediately(interfaces[i], BUFSIZ, 1, 0, error_buffer);
  }

  memcpy(interface_addrs, if_addrs, sizeof(interface_addrs));

  inited = true;
  // send igmp to join RIP multicast group
  for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
    if (pcap_out_handles[i]) {
      HAL_JoinIGMPGroup(i, if_addrs[i]);
      if (debugEnabled) {
        fprintf(stderr, "HAL_Init: Joining RIP multicast group 224.0.0.9 for %s\n",
                interfaces[i]);
      }
    }
  }
  return 0;
}

uint64_t HAL_GetTicks() {
  struct timespec tp = {0};
  clock_gettime(CLOCK_MONOTONIC, &tp);
  // millisecond
  return (uint64_t)tp.tv_sec * 1000 + (uint64_t)tp.tv_nsec / 1000000;
}

int HAL_ArpGetMacAddress(int if_index, in_addr_t ip, macaddr_t o_mac) {
  if (!inited) {
    return HAL_ERR_CALLED_BEFORE_INIT;
  }
  if (if_index >= N_IFACE_ON_BOARD || if_index < 0) {
    return HAL_ERR_INVALID_PARAMETER;
  }

  // handle multicast
  if ((ip & 0xe0) == 0xe0) {
    uint8_t multicasting_mac[6] = {0x01, 0, 0x5e, (uint8_t)((ip >> 8) & 0x7f), (uint8_t)(ip >> 16), (uint8_t)(ip >> 24)};
    memcpy(o_mac, multicasting_mac, sizeof(macaddr_t));
    return 0;
  }

  // lookup arp table
  auto it = arp_table.find(std::pair<in_addr_t, int>(ip, if_index));
  if (it != arp_table.end()) {
    memcpy(o_mac, it->second, sizeof(macaddr_t));
    return 0;
  } else if (pcap_out_handles[if_index] &&
             arp_timer[std::pair<in_addr_t, int>(ip, if_index)] + 1000 <
                 HAL_GetTicks()) {
    // not found, send arp request
    // rate limit arp request by 1 req/s
    arp_timer[std::pair<in_addr_t, int>(ip, if_index)] = HAL_GetTicks();
    if (debugEnabled) {
      fprintf(
          stderr,
          "HAL_ArpGetMacAddress: asking for ip address %s with arp request\n",
          inet_ntoa(in_addr{ip}));
    }
    uint8_t buffer[64] = {0};
    // dst mac
    for (int i = 0; i < 6; i++) {
      buffer[i] = 0xff;
    }
    // src mac
    macaddr_t mac;
    HAL_GetInterfaceMacAddress(if_index, mac);
    memcpy(&buffer[6], mac, sizeof(macaddr_t));
    // ARP
    buffer[12] = 0x08;
    buffer[13] = 0x06;
    // hardware type
    buffer[15] = 0x01;
    // protocol type
    buffer[16] = 0x08;
    // hardware size
    buffer[18] = 0x06;
    // protocol size
    buffer[19] = 0x04;
    // opcode
    buffer[21] = 0x01;
    // sender
    memcpy(&buffer[22], mac, sizeof(macaddr_t));
    memcpy(&buffer[28], &interface_addrs[if_index], sizeof(in_addr_t));
    // target
    memcpy(&buffer[38], &ip, sizeof(in_addr_t));

    pcap_inject(pcap_out_handles[if_index], buffer, sizeof(buffer));
  }
  return HAL_ERR_IP_NOT_EXIST;
}

int HAL_GetInterfaceMacAddress(int if_index, macaddr_t o_mac) {
  if (!inited) {
    return HAL_ERR_CALLED_BEFORE_INIT;
  }
  if (if_index >= N_IFACE_ON_BOARD || if_index < 0) {
    return HAL_ERR_IFACE_NOT_EXIST;
  }

  memcpy(o_mac, interface_mac[if_index], sizeof(macaddr_t));
  return 0;
}

int HAL_ReceiveIPPacket(int if_index_mask, uint8_t *buffer, size_t length,
                        macaddr_t src_mac, macaddr_t dst_mac, int64_t timeout,
                        int *if_index) {
  if (!inited) {
    return HAL_ERR_CALLED_BEFORE_INIT;
  }
  if ((if_index_mask & ((1 << N_IFACE_ON_BOARD) - 1)) == 0 ||
      (timeout < 0 && timeout != -1) || (if_index == NULL) || (buffer == NULL)) {
    return HAL_ERR_INVALID_PARAMETER;
  }

  bool flag = false;
  for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
    if (pcap_in_handles[i] && (if_index_mask & (1 << i))) {
      flag = true;
    }
  }
  if (!flag) {
    if (debugEnabled) {
      fprintf(stderr,
              "HAL_ReceiveIPPacket: no viable interfaces open for capture\n");
    }
    return HAL_ERR_IFACE_NOT_EXIST;
  }

  int64_t begin = HAL_GetTicks();
  int64_t current_time = 0;
  // Round robin
  int current_port = 0;
  struct pcap_pkthdr hdr;
  do {
    if ((if_index_mask & (1 << current_port)) == 0 ||
        !pcap_in_handles[current_port]) {
      current_port = (current_port + 1) % N_IFACE_ON_BOARD;
      continue;
    }

    const uint8_t *packet = pcap_next(pcap_in_handles[current_port], &hdr);
    if (packet && hdr.caplen >= IP_OFFSET &&
        memcmp(&packet[6], interface_mac[current_port], sizeof(macaddr_t)) ==
            0) {
      // skip outbound
      continue;
    } else if (packet && hdr.caplen >= IP_OFFSET && packet[12] == 0x08 &&
               packet[13] == 0x00) {
      // IPv4
      // TODO: what if len != caplen
      // Beware: might be larger than MTU because of offloading
      size_t ip_len = hdr.caplen - IP_OFFSET;
      size_t real_length = length > ip_len ? ip_len : length;
      memcpy(buffer, &packet[IP_OFFSET], real_length);
      memcpy(dst_mac, &packet[0], sizeof(macaddr_t));
      memcpy(src_mac, &packet[6], sizeof(macaddr_t));
      *if_index = current_port;
      return ip_len;
    } else if (packet && hdr.caplen >= IP_OFFSET && packet[12] == 0x08 &&
               packet[13] == 0x06) {
      // ARP
      // learn it
      macaddr_t mac;
      memcpy(mac, &packet[22], sizeof(macaddr_t));
      in_addr_t ip;
      memcpy(&ip, &packet[28], sizeof(in_addr_t));
      memcpy(arp_table[std::pair<in_addr_t, int>(ip, current_port)], mac,
             sizeof(macaddr_t));
      if (debugEnabled) {
        fprintf(stderr, "HAL_ReceiveIPPacket: learned MAC address of %s\n",
                inet_ntoa(in_addr{ip}));
      }

      in_addr_t dst_ip;
      memcpy(&dst_ip, &packet[38], sizeof(in_addr_t));
      // ask me: reply
      if (dst_ip == interface_addrs[current_port] && packet[21] == 0x01) {
        // reply
        uint8_t buffer[64] = {0};
        // dst mac
        memcpy(buffer, &packet[6], sizeof(macaddr_t));
        // src mac
        macaddr_t mac;
        HAL_GetInterfaceMacAddress(current_port, mac);
        memcpy(&buffer[6], mac, sizeof(macaddr_t));
        // ARP
        buffer[12] = 0x08;
        buffer[13] = 0x06;
        // hardware type
        buffer[15] = 0x01;
        // protocol type
        buffer[16] = 0x08;
        // hardware size
        buffer[18] = 0x06;
        // protocol size
        buffer[19] = 0x04;
        // opcode
        buffer[21] = 0x02;
        // sender
        memcpy(&buffer[22], mac, sizeof(macaddr_t));
        memcpy(&buffer[28], &dst_ip, sizeof(in_addr_t));
        // target
        memcpy(&buffer[32], &packet[22], sizeof(macaddr_t));
        memcpy(&buffer[38], &packet[28], sizeof(in_addr_t));

        pcap_inject(pcap_out_handles[current_port], buffer, sizeof(buffer));
        if (debugEnabled) {
          fprintf(stderr, "HAL_ReceiveIPPacket: replied ARP to %s\n",
                  inet_ntoa(in_addr{ip}));
        }
      }
      // otherwise: learn and ignore
      continue;
    }

    current_port = (current_port + 1) % N_IFACE_ON_BOARD;
    // -1 for infinity
  } while ((current_time = HAL_GetTicks()) < begin + timeout || timeout == -1);
  return 0;
}

int HAL_SendIPPacket(int if_index, uint8_t *buffer, size_t length,
                     macaddr_t dst_mac) {
  if (!inited) {
    return HAL_ERR_CALLED_BEFORE_INIT;
  }
  if (if_index >= N_IFACE_ON_BOARD || if_index < 0) {
    return HAL_ERR_INVALID_PARAMETER;
  }
  if (!pcap_out_handles[if_index]) {
    return HAL_ERR_IFACE_NOT_EXIST;
  }
  uint8_t *eth_buffer = (uint8_t *)malloc(length + IP_OFFSET);
  memcpy(eth_buffer, dst_mac, sizeof(macaddr_t));
  memcpy(&eth_buffer[6], interface_mac[if_index], sizeof(macaddr_t));
  // IPv4
  eth_buffer[12] = 0x08;
  eth_buffer[13] = 0x00;
  memcpy(&eth_buffer[IP_OFFSET], buffer, length);
  if (pcap_inject(pcap_out_handles[if_index], eth_buffer, length + IP_OFFSET) >=
      0) {
    free(eth_buffer);
    return 0;
  } else {
    if (debugEnabled) {
      fprintf(stderr, "HAL_SendIPPacket: pcap_inject failed with %s\n",
              pcap_geterr(pcap_out_handles[if_index]));
    }
    free(eth_buffer);
    return HAL_ERR_UNKNOWN;
  }
}
}