//
//  main.c
//  mastermind
//
//  Created by Jacob Probasco on 11/4/15.
//  Copyright © 2015 jprobasco. All rights reserved.
//
//  Nice features to add:
//  change evaluation to math
#include <features.h>
#include <stdio.h>
#include <string.h>         // memset()
#include <stdlib.h>
#include <sys/types.h>
// Find alternate solution to this
#include <sys/stat.h>
#include <unistd.h>
// Might not need these
#include <stdint.h>

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
    pcap = fopen("/codec/pcaps/hello.pcap", "rb");  // Open file as a data stream
    
    int pcap_fileno;                 				// Locate file number.
    pcap_fileno = fileno(pcap);                 	// Locate file number.
    fstat(pcap_fileno, &pcap_stat);                 // Load File's stats into pcap_stat.
    pcap_size = pcap_stat.st_size;                  // Set pcap_size to the size of the file.
    
    unsigned char buff[pcap_size];                  // Create buffer for a file of that size.
    memset(buff, 0, pcap_size);
    
    printf("Printing Whole PCAP\n");
    fread(buff, pcap_size, 1, pcap);
    
    prnt_head(buff, (int)pcap_size);                // Print whole PCAP
    printf("\n\n");

/*
//// Changes per-capture ////
 
// PCAP Global Header
    unsigned char glbl_magic_num[4];            // if 0xa1b2c3d4, big Endian, other: little
    unsigned char glbl_pcap_maj_ver[2];         // Assume 2
    unsigned char glbl_pcap_min_ver[2];         // assume .4
    unsigned char glbl_timez_offset[4];
    unsigned char glbl_time_accuracy[4];
    unsigned char glbl_max_length[4];           // Maximum length of capture device (likely 65,523)
    unsigned char glbl_max_length[4];           // link-layer header type (likely ethernet)
 
//// Changes per-packet ////

    // PCAP Packet Header
    unsigned char packet_timestamp[4];
    unsigned char packet_microseconds[4];
    unsigned char packet_saved_size[4];         // size in bytes in file
    unsigned char packet_live_size[4];          // data-stream size when captured
 
    /// Networking ///
    // Ethernet Header - 64 bytes
    unsigned char eth_dest[6];
    unsigned char eth_src[6];
    unsigned char eth_butt[2];                  // 08 00 = IPv4
 
    // IP Header
    unsigned char ip_hat[2];
    unsigned char ip_length[2];                 // MAXIMUM size 1500B
    unsigned char ip_id[2];
    unsigned char ip_flags[1];
    unsigned char ip_offset[1];
    unsigned char ip_ttl[1];
    unsigned char ip_protocol[1];               // 11 = UDP
    unsigned char ip_chksum[2];
    unsigned char ip_srce_pt[2];
    unsigned char ip_dest_pt[2];
 
    // UDP Header
    unsigned char udp_srce_pt[2];
    unsigned char udp_dest_pt[2];
    unsigned char udp_length[2];
    unsigned char udp_chksum[2];
 
    /// Meditrik ///
 
    // Meditrik header. - Maximum size of med_header is 24B
// Double-check after conversion
    unsigned int med_version:4;
// Double-check after conversion
    unsigned char med_squence:9;
// Double-check after conversion
    unsigned char med_type:3;
    unsigned char med_length[4];
    unsigned char med_srce_dev[8];
    unsigned char med_dest_dev[8];
 
    // Meditrik Variable Portion - Will be one of the following
 
    /// 0 - Device Status - 28B
    unsigned char med_stat_batt[16];        // IEEE 754 double-precision decimal (binary64)
    unsigned char med_stat_gluc[4];         // 0-65000
    unsigned char med_stat_caps[4];         // 0-65000
    unsigned char med_stat_omor[4];         // 0-65000
 
    /// 1 - Command Instruction - 8B

    unsigned char med_cmnd_cmnd[4];         // Sends command to device
        /// GET: STATUS(0), GPS(2)
        /// SET: GLUSCOSE(1), CAPSACIAN(3), OMORFINE(5)
        /// REPEAT(7)
        /// RESERVED(4, 6)
    unsigned char med_cmnd_param[4];        // Value for SET Commands

    /// 2 - GPS Data - 40B
    unsigned char med_gps_longitude[16];    // binary64 - degrees, can be negative
    unsigned char med_gps_latitude[16];     // binary64 - degrees, can be negative
    unsigned char med_gps_altitude[8];      // binary32

    /// 3 - Message
// INCORRECT. Must be med_length - 32 (for the med_header)
    unsigned char med_dest_payload;         // NOT NULL-terminated
 
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
