//  codec
//  encoder.c
//
//  Created by Jacob Probasco on 12/3/15.
//  Copyright © 2015 jprobasco. All rights reserved.
//
//  And now for some fun with mostly non-delimited text!

#define _BSD_SOURCE

/// Definitions ///
#define NUM_ARRAY_ELEM(a) (sizeof(a) / sizeof(*a))
#define WORD_ARRAY word_array[*chosen_array][*chosen_word]

#define WORD_ELEMENTS (sizeof(word_array[*chosen_array][*chosen_word]))/sizeof(*word_array[*chosen_array][*chosen_word])

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

// Function to verify the command being passed
int find_word(int *, int *, FILE *);
int check_set_value(int *, int *, FILE *, FILE *, const char *arg[], struct med_head *);
void usage_error (const char *filename);    // print the proper usage of encoder.c
void exit_clean(FILE *, FILE *);


int main(int argc, const char * argv[]) {
    
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
    
// READ AND PROCESS the given text file.
    
    // 0 is the mead_head. This will tell find_word what the next task is
    int next_section;
    next_section = 0;
    int next_word = 0;
    int word_result = -3;
    // int section = -3;
    
    while(!feof(text_input)){

        
        //  start with med_head
        word_result = find_word(&next_section, &next_word, text_input);
        check_set_value(&next_section, &next_word, text_input, pcap_out, argv, &med_head);

        // Get values for med_head.
        // 0-5 are for Type, Version, Sequence, From, and To respectively

    }
    
    fclose(pcap_out);
    fclose(text_input);
    return 0;

}

int find_word(int *chosen_array, int *chosen_word, FILE *text_input){
    
    // Lists of possible valid words in Meditrick Text Files
    char word_array[5][8][15] = {
        { "Type: ", "Version: ", "Sequence: ", "From: ", "To: " },
        { "Battery: ", "Glucose: ", "Capsaicin: ", "Omorfine: " },
        { "GET_STATUS: ", "SET_GLUCOSE: ", "GET_GPS: ", "SET_CAPSAICIN: ", "RESERVED(4):","SET_OMORFINE: ", "RESERVED(6): ", "REPEAT: " },
        { "Latitude: ", "Longitude: ", "Altitude: " },
        { "Message: " }
    };
    
    // initial word is Type:
    char input_char;
    int word;
    int character = 0;
    
        // Loop through a given array, word by word
        for (word = *chosen_word; word < NUM_ARRAY_ELEM(word_array[*chosen_array]); word++){
            // Loop through each character in the word element
            for (character = 0; (character != (NUM_ARRAY_ELEM(WORD_ARRAY))); character++){
                input_char = fgetc(text_input);
                
                // if encounter colon
                if ((character >= 2) && (input_char == ':')){
                    input_char = fgetc(text_input);
                    
                    // and the next char after is a space
                    if (input_char == ' '){
                        // return the word's index to main
                        return word;
                    }
                }
                
                if (WORD_ARRAY[character] != input_char){
                    return -2;
                }
                
                if (WORD_ARRAY[character] == input_char){
                    printf("%c", WORD_ARRAY[character]);
                }
            }
        }
    
    // if the program gets here, it did not find a valid word
    printf("Invalid data in file. Exiting");
    exit(0);
};

/// FUNCTIONS
int check_set_value(int *section, int *next_word, FILE *text_input, FILE *pcap_out, const char *arg[], struct med_head *func_med_head) {
    
    int value;
    //              printf("DEBUG: Tell-pre %ld\n", ftell(text_input));
    fscanf(text_input, "%d", &value);
    printf(" is: |%d|\n", value);
    
    // Med_Head
    switch (*section){
        // Cycle through the words in MED_HEAD
        case 0:
            switch (*next_word) {
                // TYPE:
                case 0:
                    // Account for errant values
                    if ((value > 3) || (value < 0)){
                        printf("Error in Text-file. Type is from 0-3. Exiting.\n");
                        exit_clean(pcap_out, text_input);
                        
                    } else {
                        *next_word = 1;
                        func_med_head->type_seq_ver.type = value;
                    }
                    break;
                // VERSION:
                case 1:
                    if (value != 1){
                        printf("Error in Text-file. Version must be 1. Exiting.\n");
                        exit_clean(pcap_out, text_input);
                    }else {
                        *next_word = 2;
                        func_med_head->type_seq_ver.version = value;
                    }
                    break;
                // SEQUENCE:
                case 2:
                    if ((value > 511) || (value < 0)){
                        printf("Error in Text-file. Sequence must be from 0-511. Exiting.\n");
                        exit_clean(pcap_out, text_input);
                    }else {
                        *next_word = 3;
                        func_med_head->type_seq_ver.squence = value;
                    }
                    break;
                // FROM:
                case 3:
                    if ((value > 9999) || (value < 0)){
                        printf("Error in Text-file. Sequence must be from 0-9999. Exiting.\n");
                        exit_clean(pcap_out, text_input);
                    }else {
                        *next_word = 4;
                        func_med_head->from = value;
                    }
                    break;
                // TO:
                case 4:
                    if ((value > 9999) || (value < 0)){
                        printf("Error in Text-file. Sequence must be from 0-9999. Exiting.\n");
                        exit_clean(pcap_out, text_input);
                    }else {
                        // Reset for next array
                        func_med_head->to = value;
                        *next_word = 0;
                        *section = func_med_head->type_seq_ver.type;

                        // process the array defined by the type processed earlier.
                        break;
                    }
            }
    // STATUS
        case 1:
    // COMMAND
        case 2:
    // GPS
        case 3:
    // MESSAGE
        case 4:;
    }
    
    if (next_word < 0){
        printf("Invalid Data in Meditrick Header Portion of %s. Exiting.\n", arg[1]);
        exit_clean(pcap_out, text_input);
    }
    
    // Go past new-line.
    fscanf(text_input, "%42[^\n]", (char*)NULL);
    fseek(text_input, sizeof(char), SEEK_CUR);
    
    return 0;
}

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

