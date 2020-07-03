#include <iostream>
#include <pcap.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ctime>
#include <cstring>
#include <sys/ioctl.h>
#include <unistd.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 10240

long uploaded = 0, downloaded = 0, uploaded_pre = 0, downloaded_pre = 0;
std::string my_ip;
long timestamp = 0;

void on_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  timespec monotime{};
  clock_gettime(CLOCK_MONOTONIC, &monotime);
  const iphdr *ip;
  const tcphdr *tcp;
  const udphdr *udp;
  ip = (iphdr *) (packet + ETH_HLEN);
  std::string src = inet_ntoa(in_addr{ip->saddr});
  std::string dst = inet_ntoa(in_addr{ip->daddr});
  std::string type = "UNKNOWN";
  int sport = 0, dport = 0;
  switch (ip->protocol) {
    case IPPROTO_TCP:
      type = "TCP";
      tcp = (tcphdr *) (packet + ETH_HLEN + ip->ihl * 4);
      sport = ntohs(tcp->source);
      dport = ntohs(tcp->dest);
      break;
    case IPPROTO_UDP:
      type = "UDP";
      udp = (udphdr *) (packet + ETH_HLEN + ip->ihl * 4);
      sport = ntohs(udp->source);
      dport = ntohs(udp->dest);
      break;
    case IPPROTO_ICMP:
      type = "ICMP";
      break;
  }
  std::cout << "Got " << type << " packet from " << src << ":" << sport <<
            " to " << dst << ":" << dport << " of " << header->len << " bytes at "
            << monotime.tv_sec * 1000 + monotime.tv_nsec / 1000000 << std::endl;

  std::cout << src << " " << my_ip << std::endl;
  if (src == my_ip) {
    uploaded += header->len;
  } else {
    downloaded += header->len;
  }

  if (timestamp == 0) {
    timestamp = monotime.tv_sec;
  }
  if (monotime.tv_sec > timestamp) {
    std::cout << "Downlink bandwidth: " << (downloaded - downloaded_pre) / (monotime.tv_sec - timestamp)
              << " bps, uplink bandwidth: " << (uploaded - uploaded_pre) / (monotime.tv_sec - timestamp)
              << " bps, at " << monotime.tv_sec * 1000 + monotime.tv_nsec / 1000000 << std::endl;
    downloaded_pre = downloaded;
    uploaded_pre = uploaded;
    timestamp = monotime.tv_sec;
  }
}

std::string get_ip(std::string nic) {
  ifreq ifr;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, nic.c_str(), IFNAMSIZ - 1);
  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);
  return inet_ntoa(((sockaddr_in *) &ifr.ifr_ifru.ifru_addr)->sin_addr);
}

int main(int argc, char **argv) {
  std::string dev = "wlp0s20f3";      /* capture device name */
  char err_buf[PCAP_ERRBUF_SIZE];    /* error buffer */
  pcap_t *handle;        /* packet capture handle */
  int num_packets = 0;      /* number of packets to capture */
  bpf_program fp{};      /* compiled filter program (expression) */
  char filter_exp[] = "ip";    /* filter expression [3] */
  bpf_u_int32 mask;      /* subnet mask */
  bpf_u_int32 net;      /* ip */

  if (pcap_lookupnet(dev.c_str(), &net, &mask, err_buf) == -1) {
    std::cerr << "Couldn't get netmask for device " << dev << ": " << err_buf << std::endl;
    net = 0;
    mask = 0;
  }
  my_ip = get_ip(dev);
  handle = pcap_open_live(dev.c_str(), SNAP_LEN, false, 1, err_buf);
  if (handle == nullptr) {
    std::cerr << "Couldn't open device " << dev << ": " << err_buf << std::endl;
    exit(EXIT_FAILURE);
  }
  if (pcap_datalink(handle) != DLT_EN10MB) {
    std::cerr << dev << " is not an Ethernet device" << std::endl;
    exit(EXIT_FAILURE);
  }
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    std::cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
    exit(EXIT_FAILURE);
  }
  pcap_loop(handle, num_packets, on_packet, nullptr);

  pcap_freecode(&fp);
  pcap_close(handle);
  return 0;
}
