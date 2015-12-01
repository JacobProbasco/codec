//
//  main.c
//  codec
//
//  Created by Jacob Probasco on 12/01/15.
//  Copyright © 2015 jprobasco. All rights reserved.
//
//  Nice features to add:

#include <stdio.h>          //fileno()
#include <string.h>         // memset()
#include <stdlib.h>
#include <sys/types.h>
// Find alternate solution to this
#include <sys/stat.h>
#include <unistd.h>
// Might not need these
#include <stdint.h>

// PCAP Global Header - 24B
struct PGBL_hdr {
    unsigned char glbl_magic_num[4];
                // if 0xa1b2c3d4, big Endian
    unsigned char glbl_pcap_maj_ver[2];
                // Assume 2
    unsigned char glbl_pcap_min_ver[2];
                // assume .4
    unsigned char glbl_timez_offset[4];
    unsigned char glbl_time_accuracy[4];
    unsigned char glbl_max_length[4];
                // Max. Len. of pcap capture dev ( assume 65,523)
    unsigned char glbl_linklay_type[4];
                // link-layer head type (ethernet)
}global_pcap_head;

// PCAP Packet Header - 16B
struct PPACK_hdr {
    unsigned char packet_timestamp[4];
    unsigned char packet_microseconds[4];
    unsigned char packet_saved_size[4];
                // size in bytes in file
    unsigned char packet_live_size[4];
                // data-stream size when captured
}packet_head;

// Ethernet Header - 14B
struct ETH_frame {
    unsigned char eth_dest[6];
    unsigned char eth_src[6];
    unsigned char eth_butt[2];
                // 08 00 = IPv4
}eth_frame;

struct IP_hdr {
    unsigned char ip_hat[2];
    unsigned char ip_length[2];
                // MAXIMUM size 1500B
    unsigned char ip_id[2];
    unsigned char ip_flags[1];
    unsigned char ip_offset[1];
    unsigned char ip_ttl[1];
    unsigned char ip_protocol[1];
                // 11 = UDP
    unsigned char ip_chksum[2];
    unsigned char ip_srce_ip[4];
    unsigned char ip_dest_ip[4];
}ip_frame;

// UDP Header
struct UDP_frame {
    unsigned char udp_srce_pt[2];
    unsigned char udp_dest_pt[2];
    unsigned char udp_length[2];
    unsigned char udp_chksum[2];
}udp_frame;

// Meditrik header. - Maximum size of med_header is 24B
struct MED_hdr {
// Double-check after conversion
    unsigned int med_version:4;
// Double-check after conversion
    unsigned int med_squence:9;
// Double-check after conversion
    unsigned int med_type:3;
    unsigned int med_length:16;
    unsigned int med_srce_dev:32;
    unsigned int med_dest_dev:32;
}med_head;

// Meditrik Variable Portion - Will be one of the following
struct MED_payload {

    /// 0 - Device Status - 28B
    struct MED_stat{
        unsigned char med_stat_batt[16];
                // IEEE 754 double-precision decimal (binary64)
        unsigned char med_stat_gluc[4];         // 0-65000
        unsigned char med_stat_caps[4];         // 0-65000
        unsigned char med_stat_omor[4];         // 0-65000
    }med_stat;

    /// 1 - Command Instruction - 8B
    struct MED_cmd{
        unsigned char cmd_out[4];
            // Sends command to device
            /// GET: STATUS(0), GPS(2)
            /// SET: GLUSCOSE(1), CAPSACIAN(3), OMORFINE(5)
            /// REPEAT(7)
            /// RESERVED(4, 6)
        unsigned char cmd_param[4];
            // Parameters for given SET Commands
    }med_cmd;

    /// 2 - GPS Data - 40B
    struct MED_gps{
        unsigned char longi[16];
            // binary64 - degrees, can be negative
        unsigned char latit[16];
            // binary64 - degrees, can be negative
        unsigned char altit[8];
            // binary32
    }med_gps;

    /// 3 - Message
    struct MED_mess{
// INCORRECT. Must be med_length - 32 (for the med_header)
        unsigned char message;
            // NOT NULL-terminated
    }med_message;
};

int main(void){
    /*

    extern int errno;                  // Error handling
    int error_n;                        // Place-holder, error number
    char secr_word[36] = { '\0' };      // Place-holder, secret word

    // Manage optional command-line arguments
    if(argc > 2){                       // Check for more than one argument, error.
        error_n = errno;
        system("clear");
        fprintf(stderr, "Error in opening %s: %s\n", argv[0], strerror(error_n));
        printf("Usage: %s <pcap file absolute path>\n", argv[0]);
        return 7;                       // Argument List too Long.
    }else if(argc == 2){                // Check for user-provided pcap.
        pcap_path = argv[1];            // Set to user-provided path.
    }else{
        // Set default path to Dictionary file.
        fprintf(stderr, "Error in opening %s: %s\n", argv[0], strerror(error_n));
        printf("Usage: %s <pcap file absolute path>\n", argv[0]);
    }
*/
    struct stat pcap_stat;                                  // For getting pcap file information
    long long pcap_size;
    int prnt_head(unsigned char *buffer, int buff_size);    // For printing the data to screen

    FILE *pcap;
    pcap = fopen("/usr/local/share/codec/hello.pcap", "rb");  // Open file as a data stream

    int pcap_fileno;                 				// Locate file number.
    pcap_fileno = fileno(pcap);                 	// Locate file number.
    fstat(pcap_fileno, &pcap_stat);                 // Load File's stats into pcap_stat.
    pcap_size = pcap_stat.st_size;                  // Set pcap_size to the size of the file.

    unsigned char buff[pcap_size];                  // Create buffer for a file of that size.
    memset(buff, 0, pcap_size);

    fread(&global_pcap_head, sizeof(global_pcap_head), 1, pcap);
    fread(&packet_head, sizeof(packet_head), 1, pcap);
	fread(&eth_frame, sizeof(eth_frame), 1, pcap);
    fread(&ip_frame, sizeof(ip_frame), 1, pcap);	
    fread(&udp_frame, sizeof(udp_frame), 1, pcap);
    fread(&med_head, sizeof(med_head), 1, pcap);

    printf("Print Global PCAP Header\n");
	prnt_head((unsigned char *)&global_pcap_head, sizeof(global_pcap_head));                // Print global Header
	
    printf("Print packet header\n");
	prnt_head((unsigned char *)&packet_head, sizeof(packet_head));                // Print packet header

	printf("Print ethernet frame\n");
	prnt_head((unsigned char *)&eth_frame, sizeof(eth_frame));		// Print Ethernet frame
	
    printf("Print IP Frame\n");
	prnt_head((unsigned char *)&ip_frame, sizeof(ip_frame));                // Print ip frame
	
    printf("Print UDP Frame\n");
	prnt_head((unsigned char *)&udp_frame, sizeof(udp_frame));                // Print udp frame

    printf("Print Meditrik Header\n");
    prnt_head((unsigned char *)&med_head, sizeof(med_head));                // Print udp frame

    printf("Print Magic_number\n");
		printf("\n%02x\n",(unsigned int)*global_pcap_head.glbl_magic_num);
    printf("\n\n");




/* EXAMPLE BIT-Masking for Flags

    char flags = 0xFB; // 11111011b char mask = 0x01; // 00000001b
    if(flags & mask){
        printf("Flag 1 set!\n");
    }
 */




//  REFERENCE.   // buffer   // each elem    // numb elements    // file
//  size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);


}

int prnt_head(unsigned char* buffer, int buff_size){
    printf("\n\n");

    int count = 0;

    for(int i = 0; i < buff_size; i++){
        printf("%02X ",buffer[i]);
        if (count == 15){
            printf("\n");
            count = -1 ;
        }
        count++;
    }
    return 0;
}
