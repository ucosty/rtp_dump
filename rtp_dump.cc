#include <iostream>
#include <fstream>
#include <stdint.h>
#include <cstdio>
#include <string>
#include <map>
#include <sstream>
using namespace std;

typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct frame_hdr_s {
	uint8_t mac_source[6];
	uint8_t mac_dest[6];
	uint8_t vlan[2];
	uint8_t dot1q[4];

	uint8_t ip_ver_length;
	uint8_t pad1[3]; // 3 octets pad
	uint8_t pad2[4]; // 4 octets pad

	uint8_t ttl;
	uint8_t protocol;
	uint16_t hdr_checksum;

	uint8_t ip_source[4];
	uint8_t ip_dest[4];
} frame_hdr_t;

typedef struct udp_hdr_s {
	uint16_t port_source;
	uint16_t port_dest;
	uint16_t length;
	uint16_t checksum;
} udp_hdr_t;

typedef struct rtp_header_s {
	uint8_t flags;
	uint8_t type;
	uint16_t seq;
	uint32_t timestamp;
	uint32_t ssrc;
} rtp_header_t;

inline void endian_swap(uint16_t& x)
{
	// Swap the byte order
    x = (x>>8) | (x<<8);
}

inline void endian_swap_wide(uint32_t& x)
{
	// Swap the byte order
	x =((x>>24)&0xff) | ((x<<8)&0xff0000) | ((x>>8)&0xff00) | ((x<<24) & 0xff000000);
}


unsigned int sip_packets = 0;
unsigned int rtp_packets = 0;
unsigned int rtcp_packets = 0;

std::map<uint32_t, FILE*> files;

ofstream payload_list;

void write_payload(uint32_t ssrc, const char *buffer, uint32_t length)
{
	FILE *output;
	if(files.find(ssrc) == files.end())
	{
		//cout << "Payload file not found" << endl;
		stringstream filename;
		filename << "0x" << std::hex << ssrc << ".raw"; 
		payload_list << "0x" << std::hex << ssrc << endl;
		output = fopen(filename.str().c_str(), "w");
		files.insert(pair<uint32_t, FILE*>(ssrc, output));
	}
	else
	{
		output = files.find(ssrc)->second;
	}
	

	fwrite(buffer, length, 1, output);
}

void read_packet(ifstream &file)
{
	char packet_buffer[2048];

	pcaprec_hdr_t packet_header;
	file.read((char*)&packet_header, sizeof(packet_header));

	frame_hdr_t frame_header;
	file.read((char*)&frame_header, sizeof(frame_header));

	if(frame_header.protocol == 17)
	{
		udp_hdr_s udp_header;
		file.read((char*)&udp_header, sizeof(udp_header));
		endian_swap(udp_header.port_source);
		endian_swap(udp_header.port_dest);
		endian_swap(udp_header.length);

		uint16_t udp_payload_len = udp_header.length - sizeof(udp_header);
		
		// Read the packet into the buffer
		file.read((char*)&packet_buffer, udp_payload_len);

		if(udp_header.port_source >= 10000 && udp_header.port_dest >= 10000)
		{
			rtp_header_s *rtp = (rtp_header_s*) packet_buffer;

			if(rtp->type == 0xc8)
			{
				rtcp_packets++;
			}
			else //if(rtp->type == 111)
			{
				endian_swap_wide(rtp->ssrc);
				uint16_t payload_length = udp_payload_len - sizeof(rtp_header_t);

				write_payload(rtp->ssrc, packet_buffer + sizeof(udp_header) + sizeof(rtp_header_s), payload_length);
				rtp_packets++;
			}
		}
		else
		{
			sip_packets++;
		}
	}
}

int main(int argc, char *argv[])
{
	cout << "rtp_dump - separate pcap file into rtp payloads" << endl;
	
	ifstream cap(argv[1], ios::binary);

	stringstream payload_name;
	payload_name << argv[1] << ".payload";

	payload_list.open(payload_name.str().c_str());

	pcap_hdr_t global_header;
	cap.read((char*)&global_header, sizeof(global_header));
	

	if(global_header.magic_number != 0xa1b2c3d4)
	{
		cout << "Packet capture file is invalid or corrupt. File magic value is " << (void*) global_header.magic_number << endl;
		cap.close();
		return 2;
	}

	while(!cap.eof())
	{
		read_packet(cap);
	}
	
	cout << "Found " << rtp_packets << " RTP packets, " << rtcp_packets << " RTCP Packets, and " << sip_packets << " SIP packets" << endl;

	payload_list.close();
	cap.close();
	return 0;
}
