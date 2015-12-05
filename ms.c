//MSG Simpson
//
//encode a text file to a pcap

#include <stdio.h>
#include <stdlib.h>			//srand system
#include <arpa/inet.h>		//uint32_t
#include <string.h>			//strdup
#include <ctype.h>			//tolower
#include <errno.h>			//perror

#include "structs.h"		//decode structs

/* Modified information for global and packet header from:
 https://wiki.wireshark.org/Development/LibpcapFileFormat
 */
FILE *test_arg(int argc, char *argv[]);
void current_status_set(current_statusw *,FILE *, int *);
int command_set(command *, FILE *,int *);
//void gps_set(gps *,FILE *, int *);
void gps_set(write_gps *,FILE *, int *);
int message_set(FILE *,FILE *, int *);

void global_set(global *);
void packet_set(packet *);
void ethernet_set(ethernet *);
void ipv4_set(ipv4 *);
void udp_set(udp *);
int meditrik_set(union ugly_union *, medhead *,FILE *, write_gps *, command *, current_statusw *, int *);

int main(int argc, char *argv[])
{
    
    if(argc < 2 ){
        printf("Invalid Syntax!\nMust provide input text file, if no output file is provided the default is: output.pcap\n");
        printf("%s <input text file> <output pcap file>\n", argv[0]);
        return 1;
    }else if (argc > 3){
        printf("Invalid Syntax!\nMust provide input text file, if no output file is provided the default is: output.pcap\n");
        printf("%s <input text file> <output pcap file>\n", argv[0]);
    }
    
    
    FILE *input = test_arg(argc, argv);//read test valid argument
    FILE *output;
    
    if(argc == 2){
        output = fopen("output.pcap", "wb"); // default
        argv[2] = "output.pcap";
    }else{//3
        output = fopen(argv[2], "wb");
    }
    
    
    ;//read test valid argument
    //output = fopen("output.pcap", "wb");
    
    unsigned char *buffer;
    unsigned int length;
    fseek(input, 0, SEEK_END);//file length
    length = ftell(input);
    fseek(input, 0, SEEK_SET);
    buffer=(unsigned char *)malloc(length+1);
    int type = 0;
    
    global myglobal;
    global_set(&myglobal);
    fwrite(&myglobal,24,1,output);//fwrite(str , 1 , sizeof(str) , fp );
    packet mypacket;
    packet_set(&mypacket);
    fwrite(&mypacket,16,1,output);//fwrite(str , 1 , sizeof(str) , fp );
    ethernet myethernet;
    ethernet_set(&myethernet);
    fwrite(&myethernet,14,1,output);//fwrite(str , 1 , sizeof(str) , fp );
    ipv4 myipv4;
    ipv4_set(&myipv4);
    fwrite(&myipv4,20,1,output);//fwrite(str , 1 , sizeof(str) , fp );
    udp myudp;
    udp_set(&myudp);
    fwrite(&myudp,8,1,output);//fwrite(str , 1 , sizeof(str) , fp );
    union ugly_union myugly_union;
    medhead mymedhead;
    current_statusw mycurrent_statusw;
    command mycommand;
    write_gps mywrite_gps;
    int current = 0;
    
    type = meditrik_set(&myugly_union, &mymedhead, input, &mywrite_gps, &mycommand, &mycurrent_statusw, &current);
    
    fwrite(&myugly_union,2,1,output);//Write ugly_union of med header
    fwrite(&mymedhead.total_length,2,1,output);//fwrite(str , 1 , sizeof(str) , fp );
    fwrite(&mymedhead.source_id,4,1,output);//fwrite(str , 1 , sizeof(str) , fp );
    fwrite(&mymedhead.destination_id,4,1,output);//fwrite(str , 1 , sizeof(str) , fp );
    
    if (type == 100){//status
        current_status_set(&mycurrent_statusw, input, &current);
        fwrite(&mycurrent_statusw,14,1,output);//fwrite(str , 1 , sizeof(str) , fp );
    }else if (type>200&&type<300){//command Payload
        int sort = command_set(&mycommand, input, &current);
        if (sort == 1){//even - no parameter
            fwrite(&mycommand.commandp,2,1,output);//fwrite(str , 1 , sizeof(str) , fp );
        }else{		//odd - parameter
            fwrite(&mycommand.commandp,2,1,output);//fwrite(str , 1 , sizeof(str) , fp );
            fwrite(&mycommand.parameter,2,1,output);//fwrite(str , 1 , sizeof(str) , fp );
        }
    }
    else if (type == 300){//gps
        gps_set(&mywrite_gps, input, &current);
        fwrite(&mywrite_gps,20,1,output);//fwrite(str , 1 , sizeof(str) , fp );
    }else if (type == 400){//message
        int total_length = message_set(input, output, &current);
        printf("returned total_length: %d\n\n",total_length);
        
        mymedhead.total_length=htons(total_length);
        fseek (output, 84, SEEK_SET);			//set in total_length in meditrik header
        fwrite(&mymedhead.total_length,2,1,output);	//fwrite the correct total_length
    }
    
    free(buffer);
    fclose(output);
    return 0;
}

FILE *test_arg(int argc, char *argv[]){
    if (argc != 3 ){//just input file for now
        printf("Error: Invalid argument!\n");
        exit(0);
    }//if
    char *filename = argv[1];//input file
    FILE *input;
    errno = 0;
    input = fopen(filename, "r+");
    if (input==NULL){
        printf("Error! File not found: %s\n",filename);
        perror ("");
        exit(0);
    }//if
    printf("File ok.\n");
    printf("opening: %s\n", filename);
    
    return input;
}

void global_set(global *myglobal){
    uint32_t temp32= 0xa1b2c3d4;
    temp32 = ntohl(temp32);			//a1b2c3d4
    myglobal->magic_number =  0xa1b2c3d4;  	// magic number
    myglobal->version_major = 0x0002; 	// major version number
    myglobal->version_minor = 0x0004; 	// minor version number
    myglobal->time_zone= 0x00000000;      	// GMT to local correction
    myglobal->sig_flags= 0x00000000;       	// accuracy of timestamps
    myglobal->snap_len= 0x00019000;       	// max length of captured packets, in octets
    myglobal->network= 0x00000001;		// data link type
}

void packet_set(packet *mypacket){
    mypacket->ts_sec = 0x00000000;		// timestamp seconds
    mypacket->ts_usec = 0x00000000;		// timestamp microseconds
    mypacket->incl_len = 0x00000000;	// number of octets of packet saved in file
    mypacket->orig_len = 0x00000000;	// actual length of packet
}

void ethernet_set(ethernet *myethernet){
    myethernet->target1_mac= 0x11111111;  	// target MAC 6 bytes
    myethernet->tarsrc_mac= 0x22221111; 	//
    myethernet->source1_mac= 0x22222222;  	// source MAC 6 bytes
    uint16_t temp16 = 0x0800;
    temp16 = htons(temp16);				//a1b2c3d4
    myethernet->protocol = temp16; 		// protocol type 0800-ipv4 0806-ARP 86DD-ipv6
}

void ipv4_set(ipv4 *myipv4){
    myipv4->ip_ver=0x45;				//4bits ipv(4)0100 or ipv(6)0110
    myipv4->tos=0x00;					//type of service 1 byte 00 default
    myipv4->total_length=0x0000;		//length of datagram, header + data
    myipv4->id=0x0000;//
    myipv4->ip_flags_offset=0x0000;		//3 bits/13 bits identify if datagram can be fragmented
    myipv4->ttl_next_chk=0x0000;		//1byte time to live 1byte next protocol
    //01 ICMP 02 IGMP 06 TCP 08 EGP 11 UDP 58 IGRP 59 OSPF
    myipv4->source_ip=0x0f01010a;		//4byte
    myipv4->trgt_ip=0x0c01000a;			//4byte
}

void udp_set(udp *myudp){
    uint16_t temp16 = 0x0435;
    temp16 = htons(temp16);
    myudp->src_prt = temp16;		//2 byte source port
    myudp->dest_prt = 0x0000;		//2 byte dest port
    myudp->udp_msglen = 0x0000;		//2 byte udp message length
    myudp->udp_chksum = 0x0000;		//2 byte udp chksum
}

int meditrik_set(union ugly_union *myugly_union, medhead *mymedhead, FILE *input, write_gps *mywrite_gps, command *mycommand, current_statusw *mycurrent_statusw, int *current){
    fseek(input,0,SEEK_END);
    int destination_id = 0, source_id = 0, total_length=0, type=0, sequence_id = 0, version = 1;// payload = 0
    unsigned int flen;
    unsigned char message[1];
    flen = ftell(input);
    printf("File length is: %d\n",flen);
    fseek(input,0, SEEK_SET);
    fscanf(input, "Version: %d\n", &version);
    myugly_union->ugly_struct.version=1;
    printf("version: %d\n",version);
    printf("version in union: %d\n",myugly_union->ugly_struct.version);
    fscanf(input, "Sequence ID: %d\n", &sequence_id);	//mymedhead->ugly_struct.sequence_id
    printf("Seq ID: in union: %d\n",myugly_union->ugly_struct.sequence_id);
    myugly_union->ugly_struct.sequence_id=sequence_id;
    fscanf(input, "From: %u\nTo: %u\n", &mymedhead->source_id, &mymedhead->destination_id);
    
    printf("version: %d\n",myugly_union->ugly_struct.version);
    printf("seq: %d\n",myugly_union->ugly_struct.sequence_id);
    printf("source: %d\n",mymedhead->source_id);
    printf("dest: %d\n",mymedhead->destination_id);
    
    mymedhead->total_length=total_length;
    source_id=htonl(mymedhead->source_id);
    mymedhead->source_id=source_id;
    destination_id=htonl(mymedhead->destination_id);
    mymedhead->destination_id=destination_id;	//4 byte dest ID ***
    printf("version: %d\n",myugly_union->ugly_struct.version);
    printf("seq: %d\n",myugly_union->ugly_struct.sequence_id);
    printf("source: %d\n",mymedhead->source_id);
    printf("dest: %d\n",mymedhead->destination_id);
    
    fpos_t position;
    fgetpos(input, &position);
    *current = (int)ftell(input);
    printf("Current before payload: %d\n",*current);
    
    char test = '0';
    if (fscanf(input, "Battery: %lf%c\n", &mycurrent_statusw->mybattery,&test)){//100
        fgetpos(input, &position);
        *current = (int)ftell(input);
        type = 0;
        myugly_union->ugly_struct.type=type;			// 3bit
        myugly_union->f16 = htons(myugly_union->f16);
        return 100;
    }
    else if (fscanf(input, "G%c", &test)){
        if (test == 'l'){
            fscanf(input, "Glucose: %hu", &mycommand->parameter);
            type = 1;
            myugly_union->ugly_struct.type=type;			// 3bit
            myugly_union->f16 = htons(myugly_union->f16);
            return 201;
        }if (test == 'E'){
            if (fscanf(input, "T%c", &test)){
                if (fscanf(input, "STATU%c", &test)){
                    type = 1;
                    myugly_union->ugly_struct.type=type;			// 3bit
                    myugly_union->f16 = htons(myugly_union->f16);
                    return 200;
                }else if (fscanf(input, "GP%c", &test)){
                    type = 1;
                    myugly_union->ugly_struct.type=type;			// 3bit
                    myugly_union->f16 = htons(myugly_union->f16);
                    return 202;
                }//else fail code
            }//if
        }//if test ==E
    }//else if G
    else if (fscanf(input, "Capsaicin: %hu", &mycommand->parameter)){
        type = 1;
        myugly_union->ugly_struct.type=type;				// 3bit
        myugly_union->f16 = htons(myugly_union->f16);
        return 203;
    }
    else if (fscanf(input, "Omorfine: %hu", &mycommand->parameter)){
        type = 1;
        myugly_union->ugly_struct.type=type;				// 3bit
        myugly_union->f16 = htons(myugly_union->f16);
        return 205;
    }
    else if (fscanf(input, "REPEA%c", &test)){
        type = 1;
        myugly_union->ugly_struct.type=type;				// 3bit
        myugly_union->f16 = htons(myugly_union->f16);
        return 207;
    }
    else if(fscanf(input, "Latitude: %lf", &mywrite_gps->w_lat)){
        type = 2;
        myugly_union->ugly_struct.type=type;				// 3bit
        myugly_union->f16 = htons(myugly_union->f16);
        return 300;
    }
    else if (fscanf(input, "Message:%c", message)){
        type = 3;
        myugly_union->ugly_struct.type=type;				// 3bit
        myugly_union->f16 = htons(myugly_union->f16);
        return 400;
    }
    return 0;
}
void current_status_set(current_statusw *mycurrent_statusw, FILE *input, int *current){
    int temp = *current;
    int t1=0,t2=0,t3=0;
    fseek (input, temp, SEEK_SET);
    mycurrent_statusw->mybattery/=100;
    
    fscanf(input, "Glucose: %d\n", &t1);
    t1 = htons(t1);
    mycurrent_statusw->glucose=t1;
    
    fscanf(input, "Capsaicin: %d\n",&t2);
    t2 = htons(t2);
    mycurrent_statusw->capsaicin=t2;
    
    fscanf(input, "Omorfine: %d\n", &t3);
    t3 = htons(t3);
    mycurrent_statusw->omorfine=t3;
}

int command_set(command *mycommand, FILE *input, int *current){
    int temp = *current;
    char test = '0';
    fseek (input, temp, SEEK_SET);					//make sure in right spot
    
    if (fscanf(input, "Glucose: %hu", &mycommand->parameter)){
        mycommand->commandp=1;
    }
    fseek (input, temp, SEEK_SET);					//make sure in right spot
    if (fscanf(input, "GET%c", &test)){
        if (fscanf(input, "STATU%c", &test)){
            mycommand->commandp=0;
        }else if (fscanf(input, "GP%c", &test)){
            mycommand->commandp=2;
        }
    }
    fseek (input, temp, SEEK_SET);					//make sure in right spot
    if (fscanf(input, "Capsaicin: %hu", &mycommand->parameter)){
        mycommand->commandp=3;
    }else if (fscanf(input, "Omorfine: %hu", &mycommand->parameter)){
        mycommand->commandp=5;
    }else if (fscanf(input, "REPEA%c",&test)){
        mycommand->parameter=12345;//random number for packet seq to resend
        mycommand->commandp=7;
    }
    uint16_t temp16 = 0x0000;
    if (mycommand->commandp % 2 == 0){				//even
        temp16=mycommand->commandp;					// 3bit
        mycommand->commandp=htons(temp16);
        return 1;
    }else{
        temp16=mycommand->commandp;					// 3bit
        mycommand->commandp=htons(temp16);
        temp16=mycommand->parameter;				// 3bit
        mycommand->parameter=htons(temp16);
        return 2;
    }
    return 0;
}

void gps_set(write_gps *mywrite_gps, FILE *input, int *current){
    int temp = *current;
    double test = 0.0, t2 = 0.0;
    float t3=0.0;
    fseek (input, temp, SEEK_SET);					//make sure in right spot
    fscanf(input, "Latitude: %lf deg. N\n", &test);
    mywrite_gps->w_lat=test;
    fscanf(input, "Longitude: %lf deg. W\n", &t2);
    mywrite_gps->w_lon=t2;
    fscanf(input, "Altitude: %f\n", &t3);
    t3 /= 6;
    mywrite_gps->w_alt=t3;	
}

int message_set(FILE *input,FILE *output, int *current){
    char message[1];
    fseek (input, *current, SEEK_SET);			//make sure we at the right spot
    fscanf(input, "Message:%c", message);			//position pointer at start of message
    
    int total_length = 0;
    char symbol;
    for ( ; fscanf(input, "%c", &symbol) != EOF; ) {
        total_length += 1;
        printf("%c", symbol);
        fputc(symbol, output);  			//Write string to file 
    }
    return total_length+12;					//return the length of the message plus header
}