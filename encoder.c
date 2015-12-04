//  codec
//  encoder.c
//
//  Created by Jacob Probasco on 12/3/15.
//  Copyright © 2015 jprobasco. All rights reserved.
//
//  And now for some fun with mostly non-delimited text!

#define _BSD_SOURCE
#include <stdio.h>          // fileno()
#include <string.h>         // memset() and strerror()
#include <stdlib.h>         // system() and others
#include <unistd.h>         // strerror()
#include "pcap_data.h"

void set_global(struct global *);
void usage_error (const char *filename);    // print the proper usage of encoder.c


int main(int argc, const char * argv[]) {

    extern int errno;                  // Error handling
    int error_n;                       // Place-holder, error number
    
    
    FILE *text_input;
    FILE *pcap_out = NULL;
    
    // Command-line arguments
    if(argc != 3){                       // Check for more than two arguments, error.
        error_n = errno;
        system("clear");
        fprintf(stderr, "Error running %s: %s\n", argv[0], strerror(error_n));
        usage_error (*argv);
        return 7;                       // Argument List too Long.
    }
    
    // Open files as a data stream
    text_input = fopen(argv[1], "rb");
    pcap_out = fopen(argv[2], "w+b");       // Writeable so we can use it if good.
    
    if(argc == 3){
        // Check both files to validate they are there and accessable.
        if (!text_input){
            printf("Error! No text file at '%s'.\n", argv[1]);
            usage_error (*argv);
        } else if (!pcap_out){
            printf("Error! No destination PCAP file at '%s'\n", argv[2]);
            usage_error (*argv);
        } else if (text_input && pcap_out){
            
            
            printf("DEBUG: Your two file locations are good.\nWho knows if they are the correct types of files. Here...We....GO...\n\n");
            
        }
    }
    
    struct global global;
    set_global(&global);
    fwrite(&global,24,1,pcap_out);
//***** Changes to data header
//***** get rid of chars

    // struct PCAP pcap_header;
    
// FIXME: Make user file more descriptive and make this a part of the encode.


    
    /*
    unsigned int default_PCAP_header[24] = { '0xD4', '0xC3', 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00};
    
    unsigned int default_PCAP_frame[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3A, 0x00, 0x00, 0x00, 0x3A, 0x00, 0x00, 0x00};
    
    unsigned int default_network_frame[42] = { 0xA6, 0x39, 0x68, 0xBE, 0xA9, 0xED, 0xC5, 0x6C, 0xBA, 0x61, 0x59, 0xEC, 0x08, 0x00, 0x45, 0x00, 0x00, 0x2C, 0x12, 0x34, 0x40, 0x00, 0xFF, 0x11, 0x53, 0x71, 0x0A, 0x00, 0x01, 0x0C, 0x0A, 0x01, 0x01, 0x0F, 0x04, 0x35, 0x05, 0x39, 0x00, 0x18, 0xAD, 0xB5 };
    
    for (int i = 0; i < 24; i++){
        fwrite(default_PCAP_header+i, sizeof(*default_PCAP_header), 2, pcap_out);
        printf("%d ", default_PCAP_header[i]);
    }
    
    for (int i=0; i < 16; i++){
        fwrite(default_PCAP_frame+i, sizeof(*default_PCAP_frame), 1, pcap_out);
    }
    
    for (int i=0; i < 46; i++){
        fwrite(default_network_frame+i, sizeof(*default_network_frame), 1, pcap_out);
    }
*/
    
    fclose(pcap_out);
    fclose(text_input);
    
    
    /*
    pcap_t *pd;
    pcap_dumper_t *pdumper;
    
    pd = pcap_open_dead(DLT_EN10MB, 65535 );
    
    pdumper = pcap_dump_open(pd, "/tmp/capture.pcap");
    if(pdumper==NULL){
        fprintf(stderr,"\nError opening output file\n");
        return -1;
    }
    
    pcap_dump(pdumper);
    
    pcap_close(pd);
    pcap_dump_close(pdumper);
    */
    
    
    med_head.version = 1;
    med_head.squence = 1;
    med_head.type = 1;
    med_head.length = 16;
    
    
    
/*
// Meditrik header. - Maximum size of med_header is 24B
struct {
    // Account for order of bits in struct.
 
    uint16_t length:16;
    uint32_t from:32;
    uint32_t to:32;
}med_head;

    med_head.nthosts = 0x
// Meditrik Variable Portion - Will be one of the following

/// 0 - Device Status - 28B
struct {
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
struct {
    uint16_t out;
    // Sends command to device
    /// GET: STATUS(0), GPS(2)
    /// SET: GLUSCOSE(1), CAPSACIAN(3), OMORFINE(5)
    /// REPEAT(7)
    /// RESERVED(4, 6)
    uint16_t param;
    // Parameters for given SET Commands
}cmnd;

/// 2 - GPS Data - 40B
struct {
    union {
        char longi[8];
        double longitude;
    };
    // binary64 - degrees, can be negative
    union {
        char latit[8];
        double latitude;
        // binary64 - degrees, can be negative
    };
    union {
        char alti[4];
        float altitude;
        // binary32
    };
}gps;

    }
*/
    return 0;
}

// print the proper usage of arguments in encoder.c
void usage_error (const char *filename){
    printf("\nUsage: %s <path to text file> <path to destination PCAP file>\n (this will overwrite that file)\n", filename);
    exit(7);
};


void set_global(struct global *myglobal){

    myglobal->magic_num =  0xa1b2c3d4;
    myglobal->maj_ver = 0x0002;
    myglobal->min_ver = 0x0004;
    myglobal->timez_offset= 0x00000000;
    myglobal->time_accuracy= 0x00000000;
    myglobal->max_length= 0x00019000;
    myglobal->linklay_type= 0x00000001;
}