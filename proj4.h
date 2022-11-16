#define MAX_PKT_SIZE 1600

struct meta_info
{
  unsigned short caplen;
  unsigned short ignored;
  unsigned int secs;
  unsigned int usecs;
};

struct pkt_info
{
  unsigned short caplen;
  double now;
  unsigned char pkt[MAX_PKT_SIZE];
  struct ether_header *ethh;
  struct ip *iph;
  struct tcphdr *tcph;
  struct udphdr *udph;
};

int errexit(char *format, char *arg);
unsigned short next_packet(int file_descriptor, struct pkt_info *pinfo);
int is_ip(struct pkt_info *pinfo);
int is_tcp(struct pkt_info *pinfo);
void summary_mode(int file_descriptor, struct pkt_info *pinfo);
void length_mode(int file_descriptor, struct pkt_info *pinfo);
void packet_printing_mode(int file_descriptor, struct pkt_info *pinfo);
void traffic_matrix_mode(int file_descriptor, struct pkt_info *pinfo);