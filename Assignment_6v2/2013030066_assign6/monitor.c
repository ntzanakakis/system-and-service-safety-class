/*
	Packet sniffer using libpcap library. v2
*/
#include<signal.h>
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include<unistd.h>
#include<math.h>
#include <stdbool.h>

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void sig_handler(int signum);
void print_totals();


FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,udp_bytes=0,tcp_bytes=0,total=0,i;	
pcap_t *handle; //handle of target device
char *tuple, **tcp_unique_tuple, **udp_unique_tuple;
int unique_tuples=0, tcp_tuples=0, udp_tuples=0;


void
usage(void)
{
	
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-i <interface>, Monitors live traffic from an interface\n"
		   "-r <filename>, Reads a pcap file \n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

int main(int argc, char *argv[])
{
	tcp_unique_tuple = malloc(1 * sizeof(*tcp_unique_tuple));
	udp_unique_tuple = malloc(1 * sizeof(*udp_unique_tuple));

	int ch;

	char errbuf[100] , *devname; //error buffer, target device name and list of devices
	int count = 1 , n;
	signal(SIGINT,sig_handler);	

	while ((ch = getopt(argc, argv, "hi:r:")) != -1) {
		switch (ch) {		
		case 'i':	
		//	strcpy(devname,optarg);
			printf("Opening device %s for sniffing ... " , optarg);
			handle = pcap_open_live(optarg , 65536 , 1 , 1000 , errbuf); //open target device for sniffing. 1 second intervals
			if (handle == NULL) 
			{
				fprintf(stderr, "Couldn't open device %s : %s\n" , optarg , errbuf);
				exit(1);
			}
			printf("Done\n");
			
			logfile=fopen("log.txt","w");
			if(logfile==NULL) 
			{
				printf("Unable to create log file.");
			}
			
			//Put the device in sniff loop

			pcap_loop(handle , -1 , process_packet , NULL); //capture packet (infinite loop), process packet with my own packet processor
			
			break;
		case 'r':
		//	strcpy(devname,optarg);
			printf("Opening file %s for scanning ... " , optarg);
			handle = pcap_open_offline(optarg , errbuf); //open target device for sniffing. 
			if (handle == NULL) 
			{
				fprintf(stderr, "Couldn't open file %s : %s\n" , optarg , errbuf);
				exit(1);
			}
			printf("Done\n");
			
			logfile=fopen("log.txt","w");
			if(logfile==NULL) 
			{
				printf("Unable to create log file.");
			}
			
			//Put the file in sniff loop
			pcap_loop(handle , -1 , process_packet , NULL); //capture packet (infinite loop), process packet with my own packet processor
				
			break;
		case 'h':
			usage();
		default:
			usage();
			break;
		}
	}
	printf("\n");
	print_totals();
	argc -= optind;
	argv += optind;	
	return 0;
}

void sig_handler(int signum){
	pcap_breakloop(handle); //if user interrupts execution, catch it and break loop to print data
}

//print final statistics of session
void print_totals(){
	printf("Total number of packets received: %d\n",total);
	printf("Total number of TCP packets received: %d\n",tcp);	
	printf("Total number of UDP packets received: %d\n",udp);
	printf("Total bytes of TCP packets received: %d\n",tcp_bytes);		
	printf("Total bytes of UDP packets received: %d\n",udp_bytes);	
	printf("Total number of network flows: %d\n", unique_tuples);	
	printf("Total number of tcp flows: %d\n", tcp_tuples);	
	printf("Total number of udp flows: %d\n", udp_tuples);	
}

//print correct packet info. can be expanded to other packet types
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	
	//Get the IP Header part of this packet , without the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol) //Check the Protocol
	{
		case 6:  //if TCP Protocol
			++tcp;
			print_tcp_packet(buffer , size);
			break;
		
		case 17: //if UDP Protocol
			++udp;
			print_udp_packet(buffer , size);
			break;
	}
	printf("TCP : %d   UDP : %d   Total (all types) : %d\r", tcp , udp , total); //live update of amount of packets 
}

//print info in ip header
void print_ip_header(const u_char * Buffer, int Size)
{
  
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) ); //
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(logfile , "\n");
	fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

//print info specific to tcp packets
void print_tcp_packet(const u_char * Buffer, int Size)
{
	int unique = 1; //flag to weed out non-unique tuples
	char temp1[6],temp2[6],temp3[6]; //temp array to save IPs and protocol for string conversion
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr)); //we need ip header info to save the IPs
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	unsigned short iphdrlen;
	
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr)); //tcp header to work with tcp packet info
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	
	fprintf(logfile , "\n\n***********************TCP Packet*************************\n");	
		
	print_ip_header(Buffer,Size); 
	tcp_bytes=tcp_bytes+Size;
	
	//to correctly find tuples, create a string that contains all of the tuple data. this way it's unique per tuple and reduces if statements
	sprintf(temp1, "%d", ntohs(tcph->source));
	sprintf(temp2, "%d", ntohs(tcph->dest));
	sprintf(temp3, "%d", iph->protocol);
	tuple = malloc(sizeof(char)*(strlen(inet_ntoa(source.sin_addr)) + strlen(inet_ntoa(dest.sin_addr)) + strlen(temp1) + strlen(temp2) + strlen(temp3)));
	strcpy(tuple, inet_ntoa(source.sin_addr));
	strcat(tuple, inet_ntoa(dest.sin_addr));
	strcat(tuple, temp1);
	strcat(tuple, temp2);
	strcat(tuple, temp3);
	if (tcp_tuples==0){ //initialize unique tuple array
		tcp_unique_tuple[0] = malloc(42 * sizeof(char));
		strcpy(tcp_unique_tuple[0], tuple); 
		unique_tuples++;
		tcp_tuples++;
	}
	for(int j=0;j<tcp_tuples;j++){ //for all unique tuples
		if (strcmp(tuple,tcp_unique_tuple[j]) == 0) //if non-unique is found, change flag
			unique = 0;
	}
	if (unique){ //if tuple is unique, allocate space to array and add it
		unique_tuples++;
		tcp_tuples++;
		tcp_unique_tuple = realloc(tcp_unique_tuple, tcp_tuples * sizeof(*tcp_unique_tuple));
		tcp_unique_tuple[tcp_tuples-1] = malloc(42 * sizeof(char*));
		strcpy(tcp_unique_tuple[tcp_tuples-1], tuple);	
	}
	
	//save the rest of the tcp packet info
	fprintf(logfile , "\n");
	fprintf(logfile , "   |-Packet number	 : %d\n" , total);
	fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	fprintf(logfile , "   |-Payload Length      : %d BYTES\n" ,Size-header_size);
	fprintf(logfile , "\n");
	fprintf(logfile , "\n***********************************************************");	
	free(tuple);
}

//print info specific to udp packets
//works exactly the same way as the tcp function
void print_udp_packet(const u_char *Buffer , int Size)
{

	int unique = 1;
	char temp1[6],temp2[6],temp3[6];
	
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;	
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	fprintf(logfile , "\n\n***********************UDP Packet*************************\n");

	udp_bytes=udp_bytes+Size;
	print_ip_header(Buffer,Size);
	
	//to correctly find tuples, create a string that contains all of the tuple data. this way it's unique per tuple and reduces if statements
	sprintf(temp1, "%d", ntohs(udph->source));
	sprintf(temp2, "%d", ntohs(udph->dest));
	sprintf(temp3, "%d", iph->protocol);
	tuple = malloc(sizeof(char)*(strlen(inet_ntoa(source.sin_addr)) + strlen(inet_ntoa(dest.sin_addr)) + strlen(temp1) + strlen(temp2) + strlen(temp3)));
	strcpy(tuple, inet_ntoa(source.sin_addr));
	strcat(tuple, inet_ntoa(dest.sin_addr));
	strcat(tuple, temp1);
	strcat(tuple, temp2);
	strcat(tuple, temp3);
	if (udp_tuples==0){
		udp_unique_tuple[0] = malloc(42 * sizeof(char));
		strcpy(udp_unique_tuple[0], tuple); 
		unique_tuples++;
		udp_tuples++;
	}
	for(int j=0;j<udp_tuples;j++){ //for all unique tuples
		if (strcmp(tuple,udp_unique_tuple[j]) == 0)
			unique = 0;
	}
	if (unique){
		unique_tuples++;
		udp_tuples++;
		udp_unique_tuple = realloc(udp_unique_tuple, udp_tuples * sizeof(*udp_unique_tuple));
		udp_unique_tuple[udp_tuples-1] = malloc(42 * sizeof(char*));
		strcpy(udp_unique_tuple[udp_tuples-1], tuple);	
	}
	
	
	
	fprintf(logfile , "   |-Packet number	 : %d\n" , total);
	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logfile , "   |-Payload Length      : %d BYTES\n" ,Size-header_size);
	
	fprintf(logfile , "\n");
	
	fprintf(logfile , "\n***********************************************************");	
	free(tuple);
}