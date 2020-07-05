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
uint32_t IP_SRC = 0;
uint32_t IP_DST = 0;
std::string PROTOCOL = "";
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
    std::cout << "Downlink bandwidth: " << (downloaded - downloaded_pre) / (monotime.tv_sec - timestamp)
              << " bps, uplink bandwidth: " << (uploaded - uploaded_pre) / (monotime.tv_sec - timestamp)
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
          ("log_file", po::value<std::string>(), "set the logger file")
          ("ip", po::value<std::string>(), "filter by IP address")
          ("port", po::value<int>(), "filter by port")
          ("src_port", po::value<int>(), "filter by src port")
          ("dst_port", po::value<int>(), "filter by dst port")
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
  if (vm.count("log_file")) {
    LOG_FILE = vm["log_file"].as<std::string>();
  }
  if (vm.count("ip_src")) {
    inet_pton(AF_INET, vm["ip_src"].as<std::string>().c_str(), &IP_SRC);
  }
  if (vm.count("ip_dst")) {
    inet_pton(AF_INET, vm["ip_dst"].as<std::string>().c_str(), &IP_DST);
  }
  if (vm.count("ip")) {
    inet_pton(AF_INET, vm["ip"].as<std::string>().c_str(), &IP);
    if (IP_SRC != 0 || IP_DST != 0) {
      std::cerr << "ip should not be set along with src/dst" << std::endl;
    }
  }
  if (vm.count("src_port")) {
    PORT_SRC = vm["src_port"].as<int>();
  }
  if (vm.count("dst_port")) {
    PORT_DST = vm["dst_port"].as<int>();
  }
  if (vm.count("port")) {
    PORT = vm["port"].as<int>();
    if (PORT_SRC > 0 || PORT_DST > 0) {
      std::cerr << "port should not be set along with src_port/dst_port" << std::endl;
    }
  }
  if (vm.count("protocol")) {
    PROTOCOL = vm["protocol"].as<std::string>();
    if (std::find(std::begin(PROTOCOLS), std::end(PROTOCOLS), PROTOCOL) == std::end(PROTOCOLS)) {
      std::cerr << "Invalid protocol: " << PROTOCOL << std::endl;
      exit(EXIT_FAILURE);
    }
  }
}

void setup_filters(pcap_t *handle) {
  bpf_program fp{};      /* compiled filter program (expression) */
  if (IP != 0) {
    char str[INET_ADDRSTRLEN];
    int res = 0;
    inet_ntop(AF_INET, &IP, str, INET_ADDRSTRLEN);
    std::cout << "ip: " << str << std::endl;
    res = pcap_compile(handle, &fp, "ip", 0, IP);
    std::cout << res << std::endl;
    res = pcap_setfilter(handle, &fp);
    std::cout << res << std::endl;
  }
}

int main(int argc, char **argv) {
  arg_parse(argc, argv);

  std::string dev = "lo";      /* capture device name */
  char err_buf[PCAP_ERRBUF_SIZE];    /* error buffer */
  pcap_t *handle;        /* packet capture handle */
  int num_packets = 0;      /* number of packets to capture */
  bpf_program fp{};      /* compiled filter program (expression) */
  char filter_exp[] = "ip";    /* filter expression [3] */
  bpf_u_int32 mask;      /* subnet mask */
  bpf_u_int32 net;      /* subnet address */

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
//  setup_filters(handle);
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
