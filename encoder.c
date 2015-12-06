//  codec
//  encoder.c
//
//  Created by Jacob Probasco on 12/3/15.
//  Copyright © 2015 jprobasco. All rights reserved.
//
//  And now for some fun with mostly non-delimited text!

#define _BSD_SOURCE
#define ARR_SIZE(a) (sizeof(a) / sizeof(*a))

#include <stdio.h>          // fileno()
#include <string.h>         // memset() and strerror()
#include <stdlib.h>         // system() and others
#include <unistd.h>         // strerror()
#include <stddef.h>         // offsetof()
#include <stdint.h>
#include <errno.h>
#include <ctype.h>

#include "pcap_data.h"

void set_PCAP(int **);
void set_global(struct global *);
void set_packet(struct packet *);
void set_ethernet(struct ethernet *);
void set_IPv4(struct IPv4 *);
void set_udp(struct UDP *);

int find_word(int chosen_array, int chosen_word, FILE *text_input);
void usage_error (const char *filename);    // print the proper usage of encoder.c
void exit_clean(FILE *, FILE *);


int main(int argc, const char * argv[]) {
    
    extern int errno;                  // Error handling
    
    FILE *text_input;
    FILE *pcap_out = NULL;
    
    // Command-line arguments
    if(argc != 3){                       // Check for more than two arguments, error.
        system("clear");
        fprintf(stderr, "Error running %s: %s\n", argv[0], strerror(errno));
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
            exit_clean(pcap_out, text_input);
        } else if (!pcap_out){
            printf("Error! No destination PCAP file at '%s'\n", argv[2]);
            usage_error (*argv);
            exit_clean(pcap_out, text_input);
        }
    }
    
    printf("DEBUG: Your two file locations are good.\nWho knows if they are the correct types of files. Here...We....GO...\n\n");
    
    // array of character arrays with the values for the default med_head
    
    int word_result = -2;
    
    // Read the given text file.
    while(!feof(text_input)){
        
        // Get values for med_head.
        // 0-5 are for Type, Version, Sequence, From, and To respectively
        for (int i = 0; i < 5; i++){
            
            // send to find_word and, if the word is there, return its index
            word_result = find_word(0, i, text_input);
            
            if (word_result == i){
                int value;
                
//              printf("DEBUG: Tell-pre %ld\n", ftell(text_input));
                fscanf(text_input, "%d", &value);
                printf(" is: |%d|\n", value);
                
                // MED_HEAD
                switch (word_result) {
                    // TYPE:
                    case 0:
                        if ((value > 3) || (value < 0)){
                            printf("Error in Text-file. Type is from 0-3. Exiting.\n");
                            exit_clean(pcap_out, text_input);
                        }
                            break;
                    // VERSION:
                    case 1:
                        printf("Version is: |%d|", value);
                        if (value != 1){
                            printf("Error in Text-file. Version must be 1. Exiting.\n");
                            exit_clean(pcap_out, text_input);
                        }
                            break;
                    // SEQUENCE:
                    case 2:
                        fread(&value, 1, 3, text_input);
                        printf("Sequence is: |%d|", value);
                        if ((value > 511) || (value < 0)){
                            printf("Error in Text-file. Sequence must be from 0-511. Exiting.\n");
                            exit_clean(pcap_out, text_input);
                        }
                            break;
                    // FROM:
                    case 3:
                        fread(&value, 1, 4, text_input);
                        printf("From is: |%d|", value);
                        if ((value > 9999) || (value < 0)){
                            printf("Error in Text-file. Sequence must be from 0-9999. Exiting.\n");
                            exit_clean(pcap_out, text_input);
                        }
                            break;
                    // TO:
                    case 4:
                        fread(&value, 1, 4, text_input);
                        printf("From is: |%d|", value);
                        if ((value > 9999) || (value < 0)){
                            printf("Error in Text-file. Sequence must be from 0-9999. Exiting.\n");
                            exit_clean(pcap_out, text_input);
                        }
                    default:
                        printf("Invalid Data in Meditrick Header Portion of %s. Exiting.\n", argv[1]);
                            break;
                }
                // Go past new-line.
                fscanf(text_input, "%42[^\n]", (char*)NULL);
                fseek(text_input, sizeof(char), SEEK_CUR);
            }
            
            // if find_word returns error, cleanly exit and tell the user
            if (word_result < 0){
                printf("Invalid Data in Meditrick Header Portion of %s. Exiting.\n", argv[1]);
                exit_clean(pcap_out, text_input);
            }
            
            // Seek past new line
            


        }
        
    }
    
/* BEGIN GOOD CODE - PUT BACK
    struct global global;
    struct packet packet;
    struct ethernet ethernet;
    struct IPv4 IPv4;
    struct UDP UDP;
    
    set_global(&global);
    set_packet(&packet);
    set_ethernet(&ethernet);
    set_IPv4(&IPv4);
    set_udp(&UDP);
    
    // Could not get this working. Supposed to loop the writing.
    // void *structures[5] = { &global, &packet, &ethernet, &IPv4, &UDP };
    // for (int i = 0; i < 6; i++){
    //     fwrite(structures[i], sizeof(*structures[i]), 1, pcap_out);
    // }
    
    fwrite(&global, sizeof(global), 1, pcap_out);
    fwrite(&packet, sizeof(packet), 1, pcap_out);
    fwrite(&ethernet, sizeof(ethernet), 1, pcap_out);
    fwrite(&IPv4, sizeof(IPv4), 1, pcap_out);
    fwrite(&UDP, sizeof(UDP), 1, pcap_out);
    
    union type_seq_ver med_tsv;
    struct med_head med_head;
    struct status status;
    struct cmnd cmnd;
    struct gps gps;
    
    // DEBUG Variables
    
    med_head.type_seq_ver.version = 1; // always 1
    med_head.type_seq_ver.squence = 1;
    med_head.type_seq_ver.type = 1;
    
    // END DEBUG variables
    
    
    // MEDITRICK HEADER
    
    ////STATUS
    if (med_head.type_seq_ver.type == 0){
        
    }
    
    ////COMMAND
    // Sends command to device
    /// GET: STATUS(0), GPS(2)
    /// SET: GLUSCOSE(1), CAPSACIAN(3), OMORFINE(5)
    /// REPEAT(7)
    /// RESERVED(4, 6)
    if (med_head.type_seq_ver.type == 1){
        if (cmnd.outgoing == 0){
            printf("GET: STATUS(0)\n");
        } else if (cmnd.outgoing == 2){
            printf("GET: GPS(2)\n");
        }
        
        else if (cmnd.outgoing == 1){
            printf("SET: GLUSCOSE(1)\n");
            
        }
        else if (cmnd.outgoing == 3){
            printf("SET: CAPSACIAN(3)\n");
        }
        
        else if (cmnd.outgoing == 5){
            printf("OMORFINE(5)\n");
        }
        else if (cmnd.outgoing == 7){
            printf("REPEAT(7)\n");
        }
        else if (cmnd.outgoing == 4 || cmnd.outgoing == 6){
            printf("RESERVED\n");
        }
        else{
            printf("Malformed Status\n");
            exit(1);
        }
        
    }
    
    ////GPS
    if (med_head.type_seq_ver.type == 2){
        
    }
    
    ////MESSAGE
    if (med_head.type_seq_ver.type == 3){
        
    }
    
    fclose(pcap_out);
    fclose(text_input);
*/
    /*
     for(int i = 0; i < 6; i++){
     printf("\n%p", &net_data + i);
     printf("\n%d", net_data[i]);
     }
     
     set_global(net_data);
     */
    
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

int find_word(int chosen_array, int chosen_word, FILE *text_input){
    
    // Lists of possible valid words in Meditrick Text Files
    
    char word_array[5][8][15] = {
        { "Type: ", "Version: ", "Sequence: ", "From: ", "To: " },
        { "Battery: ", "Glucose: ", "Capsaicin: ", "Omorfine: " },
        { "GET_STATUS: ", "SET_GLUCOSE: ", "GET_GPS: ", "SET_CAPSAICIN: ", "RESERVED(4):","SET_OMORFINE: ", "RESERVED(6): ", "REPEAT: " },
        { "Latitude: ", "Longitude: ", "Altitude: " }, { "Message: " }
    };
    
    
    char input_char;

    int word;
    int character = 0;
    
    // Loop through a given array, word by word
    for (word = 0; word < ARR_SIZE(word_array[chosen_array]); word++){
        // Loop through each character in the word element
        for (character = 0; (character != sizeof(word_array[chosen_array][chosen_word])/sizeof(*word_array[chosen_array][chosen_word])); character++){
            input_char = fgetc(text_input);
            
            //
            if ((character > 3) && (input_char == ':')){
                input_char = fgetc(text_input);
                if (input_char == ' '){
//                  printf("\nDEBUG: Your word is valid!\n");
                    return chosen_word;
                }
            }
            
            if (word_array[chosen_array][chosen_word][character] != input_char){
                return -2;
            }
            
            if (word_array[chosen_array][chosen_word][character] == input_char){
                printf("%c", word_array[chosen_array][chosen_word][character]);
            }
/* OLD CODE for cycling through all options
            // if that character does not match the current word from the file
            if (word_array[chosen_array][chosen_word][character] != input_char){
                // Rewind how many characters we've tried
                fseek(text_input, -(long)character, SEEK_CUR);
                return -1;
            }
END OLD CODE */
            
        }
        
    }
    
    // if the program gets here, it did not find a valid word
    printf("Invalid data in file. Exiting");
    exit(0);
};


// print the proper usage of arguments in encoder.c
void usage_error (const char *filename){
    printf("\nUsage: %s <path to text file> <path to destination PCAP file>\n (this will overwrite that file)\n", filename);
    exit(7);
};

void set_global(struct global *func_global){
    
    func_global->magic_num =  0xa1b2c3d4;
    func_global->maj_ver = 0x0002;
    func_global->min_ver = 0x0004;
    func_global->timez_offset = 0x00000000;
    func_global->time_accuracy = 0x00000000;
    func_global->max_length = 0x00019000;
    func_global->linklay_type = 0x00000001;
}

void set_packet(struct packet *func_packet){
    func_packet->timestamp = 0x00000000;
    func_packet->microseconds = 0x00000000;
    func_packet->saved_size = 0x00000000;
    func_packet->live_size = 0x00000000;
}

void set_ethernet(struct ethernet *func_ethernet){
    func_ethernet->dest = 0xdeadbeef;
    func_ethernet->src = 0xbeefdead;
    func_ethernet->butt = 0x0800;
}

void set_IPv4(struct IPv4 *func_IPv4){
    func_IPv4->ip_ver = 0x45;
    func_IPv4->type_service = 0x00;
    func_IPv4->packet_length = 0x0000;
    func_IPv4->IP_id = 0x0000;
    func_IPv4->flags = 0x0000;
    func_IPv4->offset = 0x0000;
    func_IPv4->ttl = 0x0000;
    func_IPv4->protocol = 0x0000;
    func_IPv4->chksum = 0x0000;
    func_IPv4->srce_ip = 0x7f000001;
    func_IPv4->dest_ip = 0x7f000002;
}

void set_udp(struct UDP *func_udp){
    func_udp->srce_pt = 0x0435;
    func_udp->dest_pt = 0x0000;
    func_udp->length = 0x0000;
    func_udp->chksum = 0x0000;
}
                
void exit_clean(FILE * pcap_out, FILE * text_input){
    fclose(pcap_out);
    fclose(text_input);
    exit(0);
}

