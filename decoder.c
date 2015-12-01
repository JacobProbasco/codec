//
//  main.c
//  codec
//
//  Created by Jacob Probasco on 12/01/15.
//  Copyright © 2015 jprobasco. All rights reserved.
//
//  Nice features to add:
#define _BSD_SOURCE
#include <stdio.h>          //fileno()
#include <string.h>         // memset()
#include "codec.h"         // little<->big endian functions
#include <stdlib.h>
#include <sys/types.h>
// Find alternate solution to this
#include <sys/stat.h>
#include <unistd.h>
// Might not need these
#include <stdint.h>

// PCAP Global Header - 24B
struct PGBL_hdr {
    unsigned char magic_num[4];
                // if 0xa1b2c3d4, big Endian
    unsigned char maj_ver[2];
                // Assume 2
    unsigned char min_ver[2];
                // assume .4
    unsigned char timez_offset[4];
    unsigned char time_accuracy[4];
    unsigned char max_length[4];
                // Max. Len. of pcap capture dev ( assume 65,523)
    unsigned char linklay_type[4];
                // link-layer head type (ethernet)
}global_pcap_head;

// PCAP Packet Header - 16B
struct PPACK_hdr {
    unsigned char timestamp[4];
    unsigned char microseconds[4];
    unsigned char saved_size[4];
                // size in bytes in file
    unsigned char live_size[4];
                // data-stream size when captured
}packet_head;

// Ethernet Header - 14B
struct ETH_frame {
    unsigned char dest[6];
    unsigned char src[6];
    unsigned char butt[2];
                // 08 00 = IPv4
}eth_frame;

struct IP_hdr {
    unsigned char hat[2];
    unsigned char length[2];
                // MAXIMUM size 1500B
    unsigned char id[2];
    unsigned char flags[1];
    unsigned char offset[1];
    unsigned char ttl[1];
    unsigned char protocol[1];
                // 11 = UDP
    unsigned char chksum[2];
    unsigned char srce_ip[4];
    unsigned char dest_ip[4];
}ip_frame;

// UDP Header
struct UDP_frame {
    unsigned char srce_pt[2];
    unsigned char dest_pt[2];
    unsigned char length[2];
    unsigned char chksum[2];
}udp_frame;

// Meditrik header. - Maximum size of med_header is 24B
struct MED_hdr {
    // Account for order of bits in struct.
    union {
        struct{
            uint16_t type:3;
            uint16_t squence:9;
            uint16_t version:4;
        };
        uint16_t nthosts;
    };
    uint16_t length:16;
    uint32_t from:32;
    uint32_t to:32;
}med_head;

// Meditrik Variable Portion - Will be one of the following

    /// 0 - Device Status - 28B
struct status{
    union {
        char batt[8];
        double battery;
    };
            // IEEE 754 double-precision decimal (binary64)
    uint16_t gluc;         // 0-65000
    uint16_t caps;         // 0-65000
    uint16_t omor;         // 0-65000
}status;

/// 1 - Command Instruction - 8B
struct cmd{
    uint16_t out;
        // Sends command to device
        /// GET: STATUS(0), GPS(2)
        /// SET: GLUSCOSE(1), CAPSACIAN(3), OMORFINE(5)
        /// REPEAT(7)
        /// RESERVED(4, 6)
    uint16_t param;
        // Parameters for given SET Commands
}cmd;

/// 2 - GPS Data - 40B
struct gps{
    unsigned char longi[16];
        // binary64 - degrees, can be negative
    unsigned char latit[16];
        // binary64 - degrees, can be negative
    unsigned char altit[8];
        // binary32
}gps;

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
    pcap = fopen("/usr/local/share/codec/command_glucose.pcap", "rb");  // Open file as a data stream

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
    
    // Network to host on packet
    med_head.nthosts = be16toh(med_head.nthosts);
    med_head.length = be16toh(med_head.length);
    med_head.from = be32toh(med_head.from);
    med_head.to = be32toh(med_head.to);
    
    printf("DEBUG: Meditrick Type is: %02X or %u\n", med_head.type, med_head.type);
    printf("DEBUG: Meditrick Total Length is: %02X or %u\n\n", med_head.length, med_head.length);
    
    printf("Version: %02X or %u\n", med_head.version, med_head.version);
    printf("Sequence: %02X or %u\n", med_head.squence, med_head.squence);
    printf("From: %02X or %u\n", med_head.from, med_head.from);
    printf("To: %02X or %u\n", med_head.to, med_head.to);
    
// Device Status Packets
    if (med_head.type == 0){
        printf("DEBUG: Device Status Type\n");
        fread(&status.batt, sizeof(status.batt), 1, pcap);
        printf("Battery: is %.2f\n", (status.battery * 100));
        
        fread(&status.gluc, sizeof(status.gluc), 1, pcap);
        status.gluc = be16toh(status.gluc);
        printf("Glucose: %02X or %u\n", status.gluc, status.gluc);
        
        fread(&status.caps, sizeof(status.caps), 1, pcap);
        status.caps = be16toh(status.caps);
        printf("Capsacian: %02X or %u\n", status.caps, status.caps);
        
        fread(&status.omor, sizeof(status.omor), 1, pcap);
        status.omor = be16toh(status.omor);
        printf("Omorfine: %02X or %u\n", status.omor, status.omor);

    }
// Command Instruction Packets
    if (med_head.type == 1){
        printf("DEBUG: Command Instruction Type\n");
        fread(&cmd.out, sizeof(cmd.out), 1, pcap);
        cmd.out = be16toh(cmd.out);
        printf("Cmd Numb: %02X or %u\n", cmd.out, cmd.out);
        
        fread(&cmd.param, sizeof(cmd.param), 1, pcap);
        cmd.param = be16toh(cmd.param);
        printf("Param: %02X or %u\n", cmd.param, cmd.param);
    }
// GPS Data Packets
    if (med_head.type == 2){
        printf("DEBUG: GPS Data Type\n");
    }
// Message Packets
    if (med_head.type == 3){
        printf("DEBUG: Message Type\n");
        char *message;
        message = (char *) realloc(message, med_head.length-12);
        fread(message, med_head.length-12, 1, pcap);
        printf("Message: %s \n", message);
        free(message);
    }
    
/* DEBUG
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
*/
    printf("Print Meditrik Header\n");
    prnt_head((unsigned char *)&med_head, sizeof(med_head));                // Print Meditrik Header
    

    

    
    printf("\n\n");

    printf("Print Meditrik Payload\n");
    prnt_head((unsigned char *)&med_head, sizeof(med_head));                // Print Meditrik Header


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
    int count = 0;

    for(int i = 0; i < buff_size; i++){
        printf("%02X ",buffer[i]);
/*        if (count == 15){
            printf("\n");
            count = -1 ;
        }
 */
        count++;
    }
    printf("\n\n");
    return 0;
}
