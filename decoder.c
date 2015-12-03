//  codec
//  decoder.c
//
//  Created by Jacob Probasco on 12/01/15.
//  Copyright © 2015 jprobasco. All rights reserved.
//
//  "Thank God that I am not my code."

// FIXME: Remove excess header files. (which ones?)

//// System-Level Header-Files
#define _BSD_SOURCE
#include <stdio.h>          //fileno()
#include <string.h>         // memset()
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>

//// codec header-files
#include "endianness.h"    // little<->big endian Linux Compatibility
#include "pcap_data.h"     // Data structures for PCAP files


int main(int argc, char *argv[]){


    extern int errno;                  // Error handling
    int error_n;                       // Place-holder, error number

    struct stat pcap_stat;                                  // For getting pcap file information
    long long pcap_size;
    int prnt_head(unsigned char *buffer, int buff_size);    // For printing the data to screen
    
    FILE *pcap;
    
// FIXME: Correct Error Handling response to not say "Undefined Error"

    // Command-line arguments
    if(argc > 2){                       // Check for more than one argument, error.
        error_n = errno;
        system("clear");
        fprintf(stderr, "Error in opening %s: %s\n", argv[0], strerror(error_n));
        printf("Usage: %s <pcap file absolute path>\n", argv[0]);
        return 7;                       // Argument List too Long.
    }else if(argc == 2){                // Check for user-provided pcap.
        pcap = fopen(argv[1], "rb");  // Open file as a data stream
    }else{
        // For classroom environment
        // "/usr/local/share/codec/command_glucose.pcap"
        fprintf(stderr, "Error in opening %s: %s\n", argv[0], strerror(error_n));
        printf("Usage: %s <pcap file absolute path>\n", argv[0]);
    }

    int pcap_fileno;                 				// Locate file number.
    pcap_fileno = fileno(pcap);                 	// Locate file number.
    fstat(pcap_fileno, &pcap_stat);                 // Load File's stats into pcap_stat.
    pcap_size = pcap_stat.st_size;                  // Set pcap_size to the size of the file.

    
// FIXME: Make PCAP header a union and write to that union... save 6 lines.
    fread(&global_pcap_head, sizeof(global_pcap_head), 1, pcap);
    fread(&packet_head, sizeof(packet_head), 1, pcap);
	fread(&eth_frame, sizeof(eth_frame), 1, pcap);
    fread(&ip_frame, sizeof(ip_frame), 1, pcap);	
    fread(&udp_frame, sizeof(udp_frame), 1, pcap);
    fread(&med_head, sizeof(med_head), 1, pcap);
    
// FIXME: Make own function
    // Transcribe Network bite-order to host bite-order
    med_head.nthosts = be16toh(med_head.nthosts);
    med_head.length = be16toh(med_head.length);
    med_head.from = be32toh(med_head.from);
    med_head.to = be32toh(med_head.to);
    
// FIXME: Remove All Commented debug code
//    printf("DEBUG: Meditrick Type is: %02X or %u\n", med_head.type, med_head.type);
//    printf("DEBUG: Meditrick Total Length is: %02X or %u\n\n", med_head.length, med_head.length);
    
    printf("Version: %u\n", med_head.version);
    printf("Sequence: %u\n", med_head.squence);
    printf("From: %u\n", med_head.from);
    printf("To: %u\n", med_head.to);

    
// FIXME: loop to deal with Multiple packets in a PCAP. malloc space as needed.
    
// Device Status Packets
    if (med_head.type == 0){
//      printf("DEBUG: Device Status Type\n");
        fread(&status.batt, sizeof(status.batt), 1, pcap);
        printf("Battery: is %.2f%%\n", (status.battery * 100));
        
        fread(&status.gluc, sizeof(status.gluc), 1, pcap);
        status.gluc = be16toh(status.gluc);
        printf("Glucose: %u\n", status.gluc);
        
        fread(&status.caps, sizeof(status.caps), 1, pcap);
        status.caps = be16toh(status.caps);
        printf("Capsacian: %u\n", status.caps);
        
        fread(&status.omor, sizeof(status.omor), 1, pcap);
        status.omor = be16toh(status.omor);
        printf("Omorfine: %u\n", status.omor);

    }
    
// Command Instruction Packets
    if (med_head.type == 1){
//      printf("DEBUG: Command Instruction Type\n");
        
        fread(&cmd.out, sizeof(cmd.out), 1, pcap);
        cmd.out = be16toh(cmd.out);
        
    /// GET Commands
        if (cmd.out == 0){
            printf("GET_STATUS(0)\n");
        }
        if (cmd.out == 2){
            printf("GET_GPS(2)\n");
        }
    /// SET Commands
        if (cmd.out == 1){
            printf("SET_GLUCOSE(1) to:\n");
            fread(&cmd.param, sizeof(cmd.param), 1, pcap);
            cmd.param = be16toh(cmd.param);
            printf("%u\n", cmd.param);
        }
        if (cmd.out == 3){
            printf("SET_CAPSAICIN(3) to:\n");
            fread(&cmd.param, sizeof(cmd.param), 1, pcap);
            cmd.param = be16toh(cmd.param);
            printf("%u\n", cmd.param);
        }
        if (cmd.out == 5){
            printf("SET_OMORFINE(5) to:\n");
            fread(&cmd.param, sizeof(cmd.param), 1, pcap);
            cmd.param = be16toh(cmd.param);
            printf("%u\n", cmd.param);
        }
    /// Repeat
        if (cmd.out == 7){
            printf("REPEAT(7)");
        }
        
        if ((cmd.out == 4) || (cmd.out == 6)){
            printf("Error: Reserved command used. Ignoring.");
        }
        
    }
    
// GPS Data Packets
    if (med_head.type == 2){
//      printf("DEBUG: GPS Data Type\n");
        fread(&gps.latit, sizeof(gps.latit), 1, pcap);
        printf("Latitude: is %2.9f ", gps.latitude);
        if ((int)gps.latitude >=0){
            printf("deg. N\n");
        } else {
            printf("deg. S\n");
        }
        
        fread(&gps.longi, sizeof(gps.longi), 1, pcap);
        printf("Longi: is %2.9f ", gps.longitude);
        
        if ((int)gps.longitude >= 0 && (int)gps.longitude <= 180){
            printf("deg. W\n");
        } else {
            printf("deg. E\n");
        }
        
        fread(&gps.alti, sizeof(gps.alti), 1, pcap);
        printf("Altitude: is %.2f ft.\n", (gps.altitude * 6));
        
    }
    
// Message Packets
    if (med_head.type == 3){
//      printf("DEBUG: Message Type\n");
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

    printf("Print Meditrik Header\n");
    prnt_head((unsigned char *)&med_head, sizeof(med_head));                // Print Meditrik Header
    
    printf("\n\n");

    printf("Print Meditrik Payload\n");
    prnt_head((unsigned char *)&med_head, sizeof(med_head));                // Print Meditrik Header
 */

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
