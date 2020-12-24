/*************************************************************
*   Author: Robin Wisniewski, wisniewski.ro@gmail.com
*   Usage: sudo ./packet_sniffer [-C]
*
*	Option(s):
*		-C: Color code output
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

//include header files that define ethernet, IP, UDP and TDP headers
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

typedef enum {false, true} bool;

int main(int argc, char *argv[])
{   
	bool color = false;
	if(argc > 1){
		if(strncmp(argv[1],"-C",2) == 0){
			color = true;
		}
	}

	//AF_PACKET    Low-level packet interface
	//SOCK_RAW	Provides raw network protocol access
	//ETH_P_ALL	 Internet Protocol packet
	// Open raw socket and capture IP packets
	int raw_socket = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
	
	//check for error
	if(raw_socket == -1)
	{
		perror("Error creating socket");
		exit(1);
	}

	//Create buffer to hold the packet information
	//Max packet size is 65535 bytes
	unsigned char *packet = (unsigned char *) malloc(65535);
	//0 out the memory
	memset(packet,0,65535);

	struct sockaddr source_addr;
	int saddr_len = sizeof(source_addr);
	while(1){
		int bytes_received = recvfrom(raw_socket,packet,65535,0,&source_addr,(socklen_t *)&saddr_len);
		
		if(bytes_received == -1)
		{
			perror("Error: ");
			exit(1);
		}
		
		// Packet structure is below 
		// [Ethernet Header 16 Bytes][IP Header 20-60 Bytes][Transport Layer Header][DATA]

		//---------Ethernet Header----------//
		//first 16 bytes are the ethernet header
		struct ethhdr *eth = (struct ethhdr *)(packet);

		//---------IP Header----------//
		//point to the ip header ==> packet + ethernet header size
		struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
		//get the ip header length. Multiply by 4 for the # of bytes
		unsigned int ip_header_length = ((unsigned int)ip->ihl)*4;

		//get the Transport layer protocol
		unsigned int t_proto = (unsigned int)ip->protocol;

		struct sockaddr_in source, dest;
		source.sin_addr.s_addr = ip->saddr;
		dest.sin_addr.s_addr = ip->daddr;

		//---------Transport Layer Header----------//
		//point to the TCP or UDP header
		// ==> packet + ethernet header size + IP header size (IHL)
		//if t_proto == 6, then the transport layer is TCP
		if(t_proto == 6 && color){
			struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header_length);
			unsigned char *data = (packet + sizeof(struct ethhdr) + ip_header_length + sizeof(struct tcphdr));

			printf("\033[1;43m************************************************************ TCP Packet ************************************************************\033[0m\n\n");
			printf("\033[1;32m------------------------- LAYER 2: ETHERNET -------------------------\n");
			printf("Source MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
			printf("Destination MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
			printf("------------------------- LAYER 3: IP -------------------------\n");
			printf("Total packet size: %d Bytes\n",ntohs(ip->tot_len));
			printf("IP Header Size: %d Bytes\n",ip_header_length);
			printf("Source IP: %s\n",inet_ntoa(source.sin_addr));
			printf("Destination IP: %s\n",inet_ntoa(dest.sin_addr));
			printf("------------------------- LAYER 4: TCP -------------------------\n");
			printf("Source Port: %d\n",ntohs(tcp->source));
			printf("Destination Port: %d\n",ntohs(tcp->dest));
			printf("Packet Sequence Number: %d \n",ntohs(tcp->seq));
			printf("Packet Acknowledgment Number: %d \n",ntohs(tcp->ack_seq));
			printf("------------------------- DATA -------------------------\n");
			int datalen = bytes_received - sizeof(struct ethhdr) + ip_header_length + sizeof(struct tcphdr);
			printf("---------- Hex Dump ----------\n");
			for(int i = 0;i<datalen;i++){
				printf("%.2X ", *(data+i));
			}
			for(int i = 0;i<datalen;i++){
				printf("%.2X ", *(data+i));
			}
			printf("\n---------- Ascii Dump ----------\n");
			for(int i = 0;i<datalen;i++){
				if(*(data+i) > 33 && *(data+i) < 127 ) {
					printf("%c", *(data+i));
				}
				else{
					printf(".");
				}
			}
			printf("\033[0m");
			printf("\n\n\033[1;43m*************************************************************************************************************************************\033[0m\n\n");
		}
		//if t_proto == 17, then the transport layer is UDP
		else if(t_proto == 17 && color){
			struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header_length);
			unsigned char *data = (packet + sizeof(struct ethhdr) + ip_header_length + sizeof(struct udphdr));

			printf("\033[1;104m************************************************************ UDP Packet ************************************************************\033[0m\n\n");
			printf("\033[1;95m------------------------- LAYER 2: ETHERNET -------------------------\n");
			printf("Source MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
			printf("Destination MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
			printf("------------------------- LAYER 3: IP -------------------------\n");
			printf("Total packet size: %d Bytes\n",ntohs(ip->tot_len));
			printf("IP Header Size: %d Bytes\n",ip_header_length);
			printf("Source IP: %s\n",inet_ntoa(source.sin_addr));
			printf("Destination IP: %s\n",inet_ntoa(dest.sin_addr));
			printf("------------------------- LAYER 4: UDP -------------------------\n");
			printf("Source Port: %d\n",ntohs(udp->source));
			printf("Destination Port: %d\n",ntohs(udp->dest));
			printf("UDP Header Size: %d Bytes\n",ntohs(udp->len));
			printf("------------------------- DATA -------------------------\n");
			int datalen = bytes_received - sizeof(struct ethhdr) + ip_header_length + sizeof(struct udphdr);
			printf("---------- Hex Dump ----------\n");
			for(int i = 0;i<datalen;i++){
				printf("%.2X ", *(data+i));
			}
			printf("\n---------- Ascii Dump ----------\n");
			for(int i = 0;i<datalen;i++){
				if(*(data+i) > 33 && *(data+i) < 127 ) {
					printf("%c", *(data+i));
				}
				else{
					printf(".");
				}
			}
			printf("\033[0m");
			printf("\n\n\033[1;104m*************************************************************************************************************************************\033[0m\n\n");
		}
		else if(t_proto == 6 && !color)
		{
			struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header_length);
			unsigned char *data = (packet + sizeof(struct ethhdr) + ip_header_length + sizeof(struct tcphdr));

			printf("************************************************************ TCP Packet ************************************************************\n\n");
			printf("------------------------- LAYER 2: ETHERNET -------------------------\n");
			printf("Source MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
			printf("Destination MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
			printf("------------------------- LAYER 3: IP -------------------------\n");
			printf("Total packet size: %d Bytes\n",ntohs(ip->tot_len));
			printf("IP Header Size: %d Bytes\n",ip_header_length);
			printf("Source IP: %s\n",inet_ntoa(source.sin_addr));
			printf("Destination IP: %s\n",inet_ntoa(dest.sin_addr));
			printf("------------------------- LAYER 4: TCP -------------------------\n");
			printf("Source Port: %d\n",ntohs(tcp->source));
			printf("Destination Port: %d\n",ntohs(tcp->dest));
			printf("Packet Sequence Number: %d \n",ntohs(tcp->seq));
			printf("Packet Acknowledgment Number: %d \n",ntohs(tcp->ack_seq));
			printf("------------------------- DATA -------------------------\n");
			int datalen = bytes_received - sizeof(struct ethhdr) + ip_header_length + sizeof(struct tcphdr);
			printf("---------- Hex Dump ----------\n");
			for(int i = 0;i<datalen;i++){
				printf("%.2X ", *(data+i));
			}
			for(int i = 0;i<datalen;i++){
				printf("%.2X ", *(data+i));
			}
			printf("\n---------- Ascii Dump ----------\n");
			for(int i = 0;i<datalen;i++){
				if(*(data+i) > 33 && *(data+i) < 127 ) {
					printf("%c", *(data+i));
				}
				else{
					printf(".");
				}
			}
			printf("\n\n*************************************************************************************************************************************\n\n");
		}
		else if(t_proto == 17 && !color){
			struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header_length);
			unsigned char *data = (packet + sizeof(struct ethhdr) + ip_header_length + sizeof(struct udphdr));

			printf("************************************************************ UDP Packet ************************************************************\n\n");
			printf("------------------------- LAYER 2: ETHERNET -------------------------\n");
			printf("Source MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
			printf("Destination MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
			printf("------------------------- LAYER 3: IP -------------------------\n");
			printf("Total packet size: %d Bytes\n",ntohs(ip->tot_len));
			printf("IP Header Size: %d Bytes\n",ip_header_length);
			printf("Source IP: %s\n",inet_ntoa(source.sin_addr));
			printf("Destination IP: %s\n",inet_ntoa(dest.sin_addr));
			printf("------------------------- LAYER 4: UDP -------------------------\n");
			printf("Source Port: %d\n",ntohs(udp->source));
			printf("Destination Port: %d\n",ntohs(udp->dest));
			printf("UDP Header Size: %d Bytes\n",ntohs(udp->len));
			printf("------------------------- DATA -------------------------\n");
			int datalen = bytes_received - sizeof(struct ethhdr) + ip_header_length + sizeof(struct udphdr);
			printf("---------- Hex Dump ----------\n");
			for(int i = 0;i<datalen;i++){
				printf("%.2X ", *(data+i));
			}
			printf("\n---------- Ascii Dump ----------\n");
			for(int i = 0;i<datalen;i++){
				if(*(data+i) > 33 && *(data+i) < 127 ) {
					printf("%c", *(data+i));
				}
				else{
					printf(".");
				}
			}
			printf("\n\n*************************************************************************************************************************************\n\n");
		}
		else{
			printf("************************************************************ Packet ************************************************************\n\n");
			printf("------------------------- LAYER 2: ETHERNET -------------------------\n");
			printf("Source MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
			printf("Destination MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
			printf("------------------------- LAYER 3: IP -------------------------\n");
			printf("Total packet size: %d Bytes\n",ntohs(ip->tot_len));
			printf("IP Header Size: %d Bytes\n",ip_header_length);
			printf("Source IP: %s\n",inet_ntoa(source.sin_addr));
			printf("Destination IP: %s\n",inet_ntoa(dest.sin_addr));
			printf("Transport Layer Protocol: %d\n",t_proto);
			printf("See: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers for protocol information\n");
			printf("\n\n*************************************************************************************************************************************\n\n");
		}
	}
	//close socket after operation
	close(raw_socket);
	
	return 0;

}

