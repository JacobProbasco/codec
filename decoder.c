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
#include <string.h>         // memset() and strerror()
#include <stdlib.h>         // system() and others
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>         // strerror()
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
    
// DEBUG: pcap = fopen("/usr/local/share/codec/command_glucose.pcap", "rb");
    int pcap_fileno;                 				// Locate file number.
    pcap_fileno = fileno(pcap);                 	// Locate file number.
    fstat(pcap_fileno, &pcap_stat);                 // Load File's stats into pcap_stat.
    pcap_size = pcap_stat.st_size;                  // Set pcap_size to the size of the file.

    
// FIXME: Make PCAP header a union and write to that union... save 6 lines.
    fread(&global, 24, 1, pcap);
    fread(&packet, 16, 1, pcap);
	fread(&ethernet, 14, 1, pcap);
    fread(&IPv4, 20, 1, pcap);
    fread(&udp_frame, 8, 1, pcap);
    
    fread(&med_head, sizeof(med_head), 1, pcap);
    
// FIXME: Make own function
    // Transcribe Network bite-order to host bite-order
    med_head.type_seq_ver.nthosts = be16toh(med_head.type_seq_ver.nthosts);
    med_head.length = be16toh(med_head.length);
    med_head.from = be32toh(med_head.from);
    med_head.to = be32toh(med_head.to);
    
    printf("Version: %u\n", med_head.type_seq_ver.version);
    printf("Sequence: %u\n", med_head.type_seq_ver.squence);
    printf("From: %u\n", med_head.from);
    printf("To: %u\n", med_head.to);

    
// FIXME: loop to deal with Multiple packets in a PCAP. malloc space as needed.
    
// Device Status Packets
    if (med_head.type_seq_ver.type == 0){
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
    if (med_head.type_seq_ver.type == 1){
        
        fread(&cmnd.outgoing, sizeof(cmnd.outgoing), 1, pcap);
        cmnd.outgoing = be16toh(cmnd.outgoing);
        
    /// GET Commands
        if (cmnd.outgoing == 0){
            printf("GET_STATUS\n");
        }
        if (cmnd.outgoing == 2){
            printf("GET_GPS\n");
        }
    /// SET Commands
        if (cmnd.outgoing == 1){
            fread(&cmnd.param, sizeof(cmnd.param), 1, pcap);
            cmnd.param = be16toh(cmnd.param);
            printf("SET_GLUCOSE to: %u\n", cmnd.param);
        }
        if (cmnd.outgoing == 3){
            fread(&cmnd.param, sizeof(cmnd.param), 1, pcap);
            cmnd.param = be16toh(cmnd.param);
            printf("SET_CAPSAICIN to: %u\n", cmnd.param);
        }
        if (cmnd.outgoing == 5){
            
            printf("SET_OMORFINE to: %u\n", cmnd.param);
        }
    /// Repeat
        if (cmnd.outgoing == 7){
            printf("REPEAT");
        }
        
        if ((cmnd.outgoing == 4) || (cmnd.outgoing == 6)){
            printf("Error: Undefined Reserved command used. Ignoring.");
        }
        
    }
    
// GPS Data Packets
    if (med_head.type_seq_ver.type == 2){
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
    if (med_head.type_seq_ver.type == 3){
        char *message;
        message = (char *) realloc(message, med_head.length-12);
        fread(message, med_head.length-12, 1, pcap);
        printf("Message: %s \n", message);
        free(message);
    }
    

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
