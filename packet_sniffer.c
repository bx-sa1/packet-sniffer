#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define PACKET_TO_HEADER(type, buffer) (type *)buffer
#define ADVANCE_PACKET(type, buffer) buffer += sizeof(type)

struct ethernet_header {
  uint8_t dest[6];
  uint8_t src[6];
  uint16_t type;
};

struct ipv4_header {
  uint32_t sec_1;
  uint32_t sec_2;
  uint32_t sec_3;
  uint32_t src;
  uint32_t dest;
};

int looping = 1;
void sigint(int signum) { looping = 0; }

/*MUST BE FREED*/
char *mac_to_string(unsigned char mac[6]) {
  char *mac_string = malloc(64);
  sprintf(mac_string, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2],
          mac[3], mac[4], mac[5]);
  return mac_string;
}

/* must be freed" */
char *ethernet_header_to_string(struct ethernet_header *header) {
  char *dest_mac = mac_to_string(header->dest);
  char *src_mac = mac_to_string(header->src);
  char *str = malloc(64);

  sprintf(str, "Dest: %s, Src: %s, Type: %d", dest_mac, src_mac, header->type);

  free(dest_mac);
  free(src_mac);
  return str;
}

char *ipv4_header_to_string(struct ipv4_header *header) {
  char *str = malloc(64);
  char version = (header->sec_1 >> 26) & 0xF;
  char ihl = (header->sec_1 >> 23) & 0xF;
  char ttl = (header->sec_3 >> 23) & 0xFF;
  char protocol = (header->sec_3 >> 15) & 0xFF;

  sprintf(str, "Version: %d, IHL: %d, TTL: %d, Protocol: %d", version, ihl, ttl,
          protocol);

  return str;
}
int main() {
  int packet_socket;
  unsigned char *buf, *temp_buf;
  struct sockaddr_ll conn_addr;
  socklen_t conn_addr_len;
  int buf_size = 65535;

  struct ethernet_header *ethernet_header;
  struct ipv4_header *ipv4_header;

  signal(SIGINT, sigint);

  packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

  while (looping) {
    temp_buf = buf = malloc(buf_size);
    if (recvfrom(packet_socket, buf, buf_size, 0, (struct sockaddr *)&conn_addr,
                 &conn_addr_len) == -1) {
      printf("Failed to read from socket\n");
      free(buf);
      return -1;
    }

    printf("Ethernet Frame:\n");
    ethernet_header = PACKET_TO_HEADER(struct ethernet_header, temp_buf);
    ADVANCE_PACKET(struct ethernet_header, temp_buf);
    char *eth_header = ethernet_header_to_string(ethernet_header);
    printf("\t %s\n", eth_header);
    free(eth_header);

    printf("IPv4 Frame:\n");
    ipv4_header = PACKET_TO_HEADER(struct ipv4_header, temp_buf);
    ADVANCE_PACKET(struct ipv4_header, temp_buf);
    char *ip_header = ipv4_header_to_string(ipv4_header);
    printf("\t %s\n", ip_header);
    free(ip_header);

    free(buf);
  }

  close(packet_socket);
  return 0;
}
