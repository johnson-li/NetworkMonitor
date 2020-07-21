#include <iostream>
#include <pcap.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ctime>
#include <cstring>
#include <sys/ioctl.h>
#include <unistd.h>
#include <boost/program_options.hpp>

namespace po = boost::program_options;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 10240

/* statics for calculating bandwidth */
long uploaded = 0, downloaded = 0, uploaded_pre = 0, downloaded_pre = 0;
std::string my_ip;
long timestamp = 0;

/* static variables */
std::vector<std::string> PROTOCOLS{"TCP", "UDP", "ICMP"};

/* configurations */
int PORT = 0;
int PORT_SRC = 0;
int PORT_DST = 0;
uint32_t IP = 0;
std::string IP_STR;
uint32_t IP_SRC = 0;
std::string IP_SRC_STR;
uint32_t IP_DST = 0;
std::string IP_DST_STR;
std::string PROTOCOL;
bpf_u_int32 NET;
bpf_u_int32 MASK;
std::string DEV = "lo";
std::string LOG_FILE = "network.log";

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
            << monotime.tv_sec * 1000 + monotime.tv_nsec / 1000000
            << " [" << header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000 << "]"
            << std::endl;

  if (src == my_ip) {
    uploaded += header->len;
  } else {
    downloaded += header->len;
  }

  if (timestamp == 0) {
    timestamp = monotime.tv_sec;
  }
  if (monotime.tv_sec > timestamp) {
    std::cout << "Downlink bandwidth: " << 8 * (downloaded - downloaded_pre) / (monotime.tv_sec - timestamp)
              << " bps, uplink bandwidth: " << 8 * (uploaded - uploaded_pre) / (monotime.tv_sec - timestamp)
              << " bps, at " << monotime.tv_sec * 1000 + monotime.tv_nsec / 1000000
              << std::endl;
    downloaded_pre = downloaded;
    uploaded_pre = uploaded;
    timestamp = monotime.tv_sec;
  }
}

std::string get_ip(const std::string &nic) {
  ifreq ifr{};
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, nic.c_str(), IFNAMSIZ - 1);
  ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);
  return inet_ntoa(((sockaddr_in *) &ifr.ifr_ifru.ifru_addr)->sin_addr);
}

void arg_parse(int argc, char **argv) {
  po::options_description desc("Allowed options");
  desc.add_options()
          ("help", "print help message")
          ("device", po::value<std::string>(), "set the NIC to capture")
          ("ip", po::value<std::string>(), "filter by IP address")
          ("port", po::value<int>(), "filter by port")
          ("src-port", po::value<int>(), "filter by src port")
          ("dst-port", po::value<int>(), "filter by dst port")
          ("src", po::value<std::string>(), "filter by source IP address")
          ("dst", po::value<std::string>(), "filter by destination IP address")
          ("protocol", po::value<std::string>(), "filter by transport layer protocol");

  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, desc), vm);
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl << std::endl;
    std::cerr << desc << std::endl;
    exit(EXIT_FAILURE);
  }
  po::notify(vm);

  if (vm.count("help")) {
    std::cout << desc << "\n";
    exit(EXIT_SUCCESS);
  }
  if (vm.count("device")) {
    DEV = vm["device"].as<std::string>();
  }
  if (vm.count("src")) {
    IP_SRC_STR = vm["src"].as<std::string>();
    inet_pton(AF_INET, IP_SRC_STR.c_str(), &IP_SRC);
  }
  if (vm.count("dst")) {
    IP_DST_STR = vm["dst"].as<std::string>();
    inet_pton(AF_INET, IP_DST_STR.c_str(), &IP_DST);
  }
  if (vm.count("ip")) {
    IP_STR = vm["ip"].as<std::string>();
    inet_pton(AF_INET, IP_STR.c_str(), &IP);
    if (IP_SRC != 0 || IP_DST != 0) {
      std::cerr << "ip should not be set along with src/dst" << std::endl;
      exit(EXIT_FAILURE);
    }
  }
  if (vm.count("src-port")) {
    PORT_SRC = vm["src-port"].as<int>();
  }
  if (vm.count("dst-port")) {
    PORT_DST = vm["dst-port"].as<int>();
  }
  if (vm.count("port")) {
    PORT = vm["port"].as<int>();
    if (PORT_SRC > 0 || PORT_DST > 0) {
      std::cerr << "port should not be set along with src_port/dst_port" << std::endl;
      exit(EXIT_FAILURE);
    }
  }
  if (vm.count("protocol")) {
    PROTOCOL = vm["protocol"].as<std::string>();
    std::transform(PROTOCOL.begin(), PROTOCOL.end(), PROTOCOL.begin(), ::toupper);
    if (std::find(std::begin(PROTOCOLS), std::end(PROTOCOLS), PROTOCOL) == std::end(PROTOCOLS)) {
      std::cerr << "Invalid protocol: " << PROTOCOL << std::endl;
      exit(EXIT_FAILURE);
    }
    if (PROTOCOL == "ICMP") {
      if (PORT > 0 || PORT_SRC > 0 || PORT_DST > 0) {
        std::cerr << "ICMP does not support port parameter" << std::endl;
        exit(EXIT_FAILURE);
      }
    }
  }
}

void setup_filters(pcap_t *handle) {
  bpf_program fp{};      /* compiled filter program (expression) */
  std::string expr;
  char net[INET_ADDRSTRLEN];
  sockaddr_in sa{};
  sa.sin_addr.s_addr = NET;
  inet_ntop(AF_INET, &(sa.sin_addr), net, INET_ADDRSTRLEN);
  if (PROTOCOL.length() > 0) {
    expr += std::string(expr.length() > 0 ? " and " : "") + "ip proto " + PROTOCOL;
  }
  if (IP != 0) {
    expr += std::string(expr.length() > 0 ? " and " : "") + "ip host " + IP_STR;
  }
  if (IP_SRC != 0) {
    expr += std::string(expr.length() > 0 ? " and " : "") + "src host " + IP_SRC_STR;
  }
  if (IP_DST != 0) {
    expr += std::string(expr.length() > 0 ? " and " : "") + "dst host " + IP_DST_STR;
  }
  if (PORT != 0) {
    expr += std::string(expr.length() > 0 ? " and " : "") + "port " + std::to_string(PORT);
  }
  if (PORT_SRC != 0) {
    expr += std::string(expr.length() > 0 ? " and " : "") + "src port " + std::to_string(PORT_SRC);
  }
  if (PORT_DST != 0) {
    expr += std::string(expr.length() > 0 ? " and " : "") + "dst port " + std::to_string(PORT_DST);
  }
  std::cout << "Pcap filter: " << expr << " on NIC: " << net << std::endl;
  char str[INET_ADDRSTRLEN];
  int res = 0;
  inet_ntop(AF_INET, &IP, str, INET_ADDRSTRLEN);
  res = pcap_compile(handle, &fp, expr.c_str(), 0, NET);
  if (res != 0) {
    std::cerr << "Failed to call pcap_compile" << std::endl;
  }
  res = pcap_setfilter(handle, &fp);
  if (res != 0) {
    std::cerr << "Failed to call pcap_setfilter" << std::endl;
  }
}

int main(int argc, char **argv) {
  arg_parse(argc, argv);

  char err_buf[PCAP_ERRBUF_SIZE];    /* error buffer */
  pcap_t *handle;        /* packet capture handle */
  int num_packets = 0;      /* number of packets to capture */
  bpf_program fp{};      /* compiled filter program (expression) */

  if (pcap_lookupnet(DEV.c_str(), &NET, &MASK, err_buf) == -1) {
    std::cerr << "Couldn't get netmask for device " << DEV << ": " << err_buf << std::endl;
    exit(EXIT_FAILURE);
  } else {
    std::cout << "Listening on " << DEV << std::endl;
  }
  my_ip = get_ip(DEV);
  handle = pcap_open_live(DEV.c_str(), SNAP_LEN, false, 1, err_buf);
  if (handle == nullptr) {
    std::cerr << "Couldn't open device " << DEV << ": " << err_buf << std::endl;
    exit(EXIT_FAILURE);
  }
  if (pcap_datalink(handle) != DLT_EN10MB) {
    std::cerr << DEV << " is not an Ethernet device" << std::endl;
    exit(EXIT_FAILURE);
  }
  setup_filters(handle);
  pcap_loop(handle, num_packets, on_packet, nullptr);

  pcap_freecode(&fp);
  pcap_close(handle);
  return 0;
}
