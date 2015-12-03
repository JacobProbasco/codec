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

int main(int argc, const char * argv[]) {

    extern int errno;                  // Error handling
    int error_n;                       // Place-holder, error number
    
    FILE *text_input;
    FILE *pcap_out;
    
    // Command-line arguments
    if(argc > 3){                       // Check for more than one argument, error.
        error_n = errno;
        system("clear");
        fprintf(stderr, "Error in opening %s: %s\n", argv[0], strerror(error_n));
        printf("Usage: %s <path to text file> < path to destination PCAP file>\n (this will overwrite that file)", argv[0]);
        return 7;                       // Argument List too Long.
    }else if(argc == 3){
        
        // Open files as a data stream
        text_input = fopen(argv[1], "rb");
        pcap_out = fopen(argv[2], "rwb");       // Writeable so we can use it if good.
        
        // Check both files to validate they are there and accessable.
        if (text_input && pcap_out){
            printf("DEBUG: Your two file locations are good. Who knows if they are the correct types of files.\n");
            exit(0);
        }else if (!text_input){
            printf("Error! No text file at '%s'.\n", argv[1]);
        }else if (!pcap_out){
            printf("Error! No destination PCAP file at '%s'\n", argv[2]);
        }
        printf("Usage: %s <path to text file> <path to destination PCAP file>\n (this will overwrite that file)\n", argv[0]);
        exit(1);
    }
    return 0;
}
