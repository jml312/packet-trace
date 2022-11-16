/*
 * Name:        Josh Levy
 * Case ID:     jml312
 * Filename:    proj4.c
 * Created:     10/15/22
 * Description: This program takes a trace file and
 * a mode (S for summary, L for length, P for packet, M for matrix and outputs corresponding information about the trace file.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "proj4.h"
#include "hashtable.h"

#define IP_LENGTH 17
#define HT_SIZE 49157 // prime number for hashtable size
#define NULL_CHAR '\0'
#define ERROR 1

int main(int argc, char *argv[])
{
  int opt;
  char optopt_char[2];
  char *trace_file = NULL;
  char mode[2];
  FILE *file_pointer = NULL;
  struct pkt_info pinfo;

  /* read command line arguments */
  while ((opt = getopt(argc, argv, ":t:slpm")) != -1)
  {
    switch (opt)
    {
    case 't':
      trace_file = optarg;
      break;
    case 's':
    case 'l':
    case 'p':
    case 'm':
      if (mode[0] != NULL_CHAR)
      {
        errexit("ERROR: only one mode can be specified", NULL);
      }
      sprintf(mode, "%c", opt);
      break;
    case ':':
    {
      sprintf(optopt_char, "%c", optopt);
      errexit("ERROR: option -%s requires an argument", optopt_char);
      break;
    }
    case '?':
    {
      sprintf(optopt_char, "%c", optopt);
      errexit("ERROR: unknown option -%s", optopt_char);
      break;
    }
    }
  }

  /* check for empty trace file or mode */
  if (!trace_file && mode[0] == NULL_CHAR)
  {
    errexit("ERROR: trace file and mode must be specified\nERROR: must specify one of -s, -l, -p, or -m", NULL);
  }
  else if (!trace_file)
  {
    errexit("ERROR: trace file and mode must be specified", NULL);
  }
  else if (mode[0] == NULL_CHAR)
  {
    errexit("ERROR: must specify one of -s, -l, -p, or -m", NULL);
  }

  /* open trace file */
  file_pointer = fopen(trace_file, "r");
  if (!file_pointer)
  {
    errexit("ERROR: could not open trace file %s", trace_file);
  }

  /* process trace file */
  switch (mode[0])
  {
  case 's':
    summary_mode(fileno(file_pointer), &pinfo);
    break;
  case 'l':
    length_mode(fileno(file_pointer), &pinfo);
    break;
  case 'p':
    packet_printing_mode(fileno(file_pointer), &pinfo);
    break;
  case 'm':
    traffic_matrix_mode(fileno(file_pointer), &pinfo);
    break;
  }

  fclose(file_pointer);
  return 0;
}

/* exit program with error message */
int errexit(char *format, char *arg)
{
  fprintf(stderr, format, arg);
  fprintf(stderr, "\n");
  exit(ERROR);
}

/* file_descriptor - an open file to read packets from
   pinfo - allocated memory to put packet info into for one packet
   total_pkts - total number of packets read so far
   ip_pkts - number of IP packets read so far

   returns:
   1 - a packet was read and pinfo is setup for processing the packet
   0 - we have hit the end of the file and no packet is available
 */
unsigned short next_packet(int file_descriptor, struct pkt_info *pinfo)
{
  struct meta_info meta;
  int bytes_read;

  memset(pinfo, 0x0, sizeof(struct pkt_info));
  memset(&meta, 0x0, sizeof(struct meta_info));

  /* read the meta information */
  bytes_read = read(file_descriptor, &meta, sizeof(meta));
  if (!bytes_read)
  {
    return (0);
  }
  if (bytes_read < sizeof(meta))
  {
    errexit("ERROR: cannot read meta information", NULL);
  }
  pinfo->now = (double)ntohl(meta.secs) + (double)ntohl(meta.usecs) / 1000000.0;
  pinfo->caplen = ntohs(meta.caplen);
  if (pinfo->caplen > MAX_PKT_SIZE)
  {
    errexit("ERROR: packet too big", NULL);
  }

  /* read the packet contents */
  bytes_read = read(file_descriptor, pinfo->pkt, pinfo->caplen);
  if (bytes_read < 0)
  {
    errexit("ERROR: error reading packet", NULL);
  }
  if (bytes_read < pinfo->caplen)
  {
    errexit("ERROR: unexpected end of file encountered", NULL);
  }

  /* set up ethernet header */
  if (bytes_read < sizeof(struct ether_header))
  {
    return (1);
  }
  pinfo->ethh = (struct ether_header *)pinfo->pkt;
  pinfo->ethh->ether_type = ntohs(pinfo->ethh->ether_type);
  if (pinfo->ethh->ether_type != ETHERTYPE_IP)
  {
    return (1);
  }

  /* set up IP header */
  if (pinfo->caplen < sizeof(struct ether_header) + sizeof(struct ip))
  {
    return (1);
  }
  pinfo->iph = (struct ip *)(pinfo->pkt + sizeof(struct ether_header));
  pinfo->iph->ip_len = ntohs(pinfo->iph->ip_len);

  unsigned short ip_size = sizeof(struct ether_header) + (pinfo->iph->ip_hl * 4);

  if (pinfo->iph->ip_p == IPPROTO_TCP)
  {
    pinfo->iph->ip_p = 'T';
    /* set up TCP header */
    if (pinfo->caplen < ip_size + sizeof(struct tcphdr))
    {
      return (1);
    }
    pinfo->tcph = (struct tcphdr *)(pinfo->pkt + ip_size);
    pinfo->tcph->th_sport = ntohs(pinfo->tcph->th_sport);
    pinfo->tcph->th_dport = ntohs(pinfo->tcph->th_dport);
    pinfo->tcph->th_win = ntohs(pinfo->tcph->th_win);
    pinfo->tcph->th_seq = ntohl(pinfo->tcph->th_seq);
    pinfo->tcph->th_ack = ntohl(pinfo->tcph->th_ack);
  }
  else if (pinfo->iph->ip_p == IPPROTO_UDP)
  {
    pinfo->iph->ip_p = 'U';
    /* set up UDP header */
    if (pinfo->caplen < ip_size + sizeof(struct udphdr))
    {
      return (1);
    }
    pinfo->udph = (struct udphdr *)(pinfo->pkt + ip_size);
  }
  else
  {
    pinfo->iph->ip_p = '?';
  }

  return (1);
}

/* pinfo: packet information
 * return: 1 if packet is IP, 0 otherwise
 */
int is_ip(struct pkt_info *pinfo)
{
  return pinfo->ethh->ether_type == ETHERTYPE_IP;
}

/* pinfo: packet information
 * return: 1 if packet is TCP, 0 otherwise
 */
int is_tcp(struct pkt_info *pinfo)
{
  return pinfo->iph->ip_p == 'T';
}

/* file_descriptor - an open file to read packets from
   pinfo - allocated memory to put packet info into for one packet

    process the trace file in summary mode (-s)
 */
void summary_mode(int file_descriptor, struct pkt_info *pinfo)
{
  char *first_time = (char *)malloc(IP_LENGTH);
  char *last_time = NULL;
  int total_pkts = 0;
  int ip_pkts = 0;

  while (next_packet(file_descriptor, pinfo))
  {
    if (++total_pkts == 1)
    {
      sprintf(first_time, "%f", pinfo->now);
    }
    last_time = (char *)malloc(IP_LENGTH);
    sprintf(last_time, "%f", pinfo->now);
    if (pinfo->iph)
    {
      ip_pkts++;
    }
  }

  printf("FIRST PKT: %s\n", first_time);
  printf("LAST PKT: %s\n", last_time);
  printf("TOTAL PACKETS: %i\n", total_pkts);
  printf("IP PACKETS: %i\n", ip_pkts);
}

/* file_descriptor - an open file to read packets from
   pinfo - allocated memory to put packet info into for one packet

    process the trace file in length mode (-l)
 */
void length_mode(int file_descriptor, struct pkt_info *pinfo)
{
  double ts;
  unsigned short caplen;
  u_short ip_len;
  u_int iphl;
  u_char transport;
  u_int trans_hl;
  uint payload_len;

  while (next_packet(file_descriptor, pinfo))
  {
    if (is_ip(pinfo))
    {
      ts = pinfo->now;
      caplen = pinfo->caplen;
      if (!pinfo->iph)
      {
        printf("%f %hu - - - - -\n", ts, caplen);
      }
      else
      {
        ip_len = pinfo->iph->ip_len;
        iphl = pinfo->iph->ip_hl * 4;
        transport = pinfo->iph->ip_p;
        if (pinfo->tcph)
        {
          trans_hl = pinfo->tcph->th_off * 4;
          payload_len = ip_len - (iphl + trans_hl);
          printf("%f %hu %hu %u %c %d %d\n", ts, caplen, ip_len, iphl, transport, trans_hl, payload_len);
        }
        else if (pinfo->udph)
        {
          trans_hl = sizeof(struct udphdr);
          payload_len = ip_len - (iphl + trans_hl);
          printf("%f %hu %hu %u %c %d %d\n", ts, caplen, ip_len, iphl, transport, trans_hl, payload_len);
        }
        else if (transport == '?')
        {
          printf("%f %hu %hu %u ? ? ?\n", ts, caplen, ip_len, iphl);
        }
        else
        {
          printf("%f %hu %hu %u %c - -\n", ts, caplen, ip_len, iphl, transport);
        }
      }
    }
  }
}

/* file_descriptor - an open file to read packets from
   pinfo - allocated memory to put packet info into for one packet

    process the trace file in IPv4/TCP packet printing mode (-p)
 */
void packet_printing_mode(int file_descriptor, struct pkt_info *pinfo)
{
  double ts;
  char *source_ip = (char *)malloc(IP_LENGTH);
  char *dest_ip = (char *)malloc(IP_LENGTH);
  u_char ip_ttl;
  unsigned short src_port;
  unsigned short dst_port;
  unsigned short window;
  unsigned int seqno;
  unsigned int ackno;

  while (next_packet(file_descriptor, pinfo))
  {
    if (is_ip(pinfo) && is_tcp(pinfo))
    {
      ts = pinfo->now;
      sprintf(source_ip, "%s", inet_ntoa(pinfo->iph->ip_src));
      sprintf(dest_ip, "%s", inet_ntoa(pinfo->iph->ip_dst));
      ip_ttl = pinfo->iph->ip_ttl;
      src_port = pinfo->tcph->th_sport;
      dst_port = pinfo->tcph->th_dport;
      window = pinfo->tcph->th_win;
      seqno = pinfo->tcph->th_seq;
      if (!(pinfo->tcph->th_flags & TH_ACK))
      {
        printf("%f %s %s %d %d %d %d %u -\n", ts, source_ip, dest_ip, ip_ttl, src_port, dst_port, window, seqno);
      }
      else
      {
        ackno = pinfo->tcph->th_ack;
        printf("%f %s %s %d %d %d %d %u %u\n", ts, source_ip, dest_ip, ip_ttl, src_port, dst_port, window, seqno, ackno);
      }
    }
  }
}

/* file_descriptor - an open file to read packets from
   pinfo - allocated memory to put packet info into for one packet

    process the trace file in traffic matrix mode (-m)
 */
void traffic_matrix_mode(int file_descriptor, struct pkt_info *pinfo)
{
  char *source_ip = (char *)malloc(IP_LENGTH);
  char *dest_ip = (char *)malloc(IP_LENGTH);
  u_short ip_len;
  u_int iphl;
  u_int trans_hl;
  unsigned int traffic_volume;
  Hashtable *ht = ht_create(HT_SIZE);

  while (next_packet(file_descriptor, pinfo))
  {
    if (is_ip(pinfo) && is_tcp(pinfo))
    {
      sprintf(source_ip, "%s", inet_ntoa(pinfo->iph->ip_src));
      sprintf(dest_ip, "%s", inet_ntoa(pinfo->iph->ip_dst));
      char *key = (char *)malloc(IP_LENGTH * 2);
      sprintf(key, "%s %s", source_ip, dest_ip);
      ip_len = pinfo->iph->ip_len;
      iphl = pinfo->iph->ip_hl * 4;
      trans_hl = pinfo->tcph->th_off * 4;
      traffic_volume = ip_len - (iphl + trans_hl);
      ht_insert(ht, key, traffic_volume);
    }
  }

  ht_print(ht);
}