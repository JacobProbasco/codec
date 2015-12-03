//  codec
//  packet.h
//
//
//  Created by Jacob Probasco on 12/3/15.
//  Copyright © 2015 jprobasco. All rights reserved.
//
//  The secret is in the sauce.

#ifndef PCAP_STRUCTS_H
#define PCAP_STRUCTS_H

// PCAP Global Header - 24B
struct PGBL_hdr {
    unsigned char magic_num[4];
    // Magic Number
    // if 0xa1b2c3d4, big Endian
    unsigned char maj_ver[2];
    // Major Version Number
    // Assume 2
    unsigned char min_ver[2];
    // Minor Version Number
    // assume .4
    unsigned char timez_offset[4];
    // GMT to Local time zone
    unsigned char time_accuracy[4];
    // Length of time accuracy
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
    unsigned int ip_ver:8;
    // IPv4 - 0b0100; IPv6 - 0b0110
    //	unsigned int ihl : 4;
    // IP Header Length 4 bits min 5 = 20 bytes
    unsigned int type_service:8;
    // Default is 00
    unsigned char packet_length[2];
    // MAXIMUM size 1500B
    // length of packet (including header and data)
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

#endif /* packet_h */
