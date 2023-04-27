#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#pragma pack(1)

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
    u_char DA[6];
    u_char SA[6];
    uint16_t Type;
} Ethernet;

typedef struct {
    uint8_t HL : 4;
    uint8_t Version : 4;
    uint8_t ToS;
    uint16_t TL;
    uint16_t Id;
    uint16_t Fragment;
    uint8_t TTL;
    uint8_t P_Type;
    uint16_t Checksum;
    uint32_t SA;
    uint32_t DA;
} IP;

typedef struct {
    uint16_t SA;
    uint16_t DA;
    uint32_t Seq;
    uint32_t Ack;

    uint8_t Res : 4; //Res first
    uint8_t HL : 4;
    uint8_t Flags;
    uint16_t Win;
    uint16_t Checksum;
    uint16_t Urgent_P;
    uint8_t Data[];
} TCP;

typedef struct {
    Ethernet ether;
    IP ip;
    TCP tcp;
} Packet;

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_mac(u_char data[6]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", data[0], data[1], data[2], data[3], data[4], data[5]);
}

void print_ip(u_int32_t data) {
    u_int8_t* p;
    p = (u_int8_t*)&data;
    printf("%u.%u.%u.%u\n", *p, *(p+1), *(p+2), *(p+3));
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
    printf("##############################\n");
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
        Packet *p;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        p = (Packet*)packet;

        if(ntohs(p->ether.Type) != 0x0800) continue;
        if(p->ip.P_Type != 0x06) continue;

        u_char* data;
        u_int32_t data_length = ntohs(p->ip.TL) - (p->ip.HL)*4 - (p->tcp.HL)*4 ;

        data = (u_char*)&p->tcp + (p->tcp.HL)*4;

        printf("\n-----Ethernet Header-----\n");
        printf("Src mac : ");
        print_mac(p->ether.DA);
        printf("Dst mac : ");
        print_mac(p->ether.SA);

        printf("\n-----IP Header-----n");
        printf("Src ip : ");
        print_ip(p->ip.SA);
        printf("Dst ip : ");
        print_ip(p->ip.DA);

        printf("\n-----TCP Header------n");
        printf("Src port : %d", ntohs(p->tcp.SA));
        printf("Dct port : %d\n", ntohs(p->tcp.DA));

        printf("\n-----Payload(Data)-----");
        if(data_length == 0) printf("No Data\n");
        else printf("Data(4bytes) : 0x%02x%02x%02x%02x\n", *data, *(data+1), *(data+2), *(data+3));

        printf("\n##############################\n");
	}

	pcap_close(pcap);
}

