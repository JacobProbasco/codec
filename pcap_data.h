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

typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct ethernet_hdr_s {
    uint8_t dst[6];    /* destination host address */
    uint8_t src[6];    /* source host address */
    uint16_t type;     /* IP? ARP? RARP? etc */
} ethernet_hdr_t;

typedef struct ip_hdr_s {
    uint8_t  ip_hl:4, /* both fields are 4 bits */
ip_v:4;
    uint8_t        ip_tos;
    uint16_t       ip_len;
    uint16_t       ip_id;
    uint16_t       ip_off;
    uint8_t        ip_ttl;
    uint8_t        ip_p;
    uint16_t       ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
}ip_hdr_t;

typedef struct udp_header
{
    uint16_t src;
    uint16_t dst;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

// Meditrik header. - Maximum size of med_header is 24B
struct med_head{
    // Account for order of bits in struct.
    union type_seq_ver {
        struct{
            uint16_t type:3;
            uint16_t squence:9;
            uint16_t version:4;
        };
        uint16_t nthosts;
    }type_seq_ver;
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
struct cmnd{
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

// PCAP Global Header - 24B
struct global{
    uint32_t magic_num;
    // Magic Number
    // if 0xa1b2c3d4, big Endian
    uint16_t maj_ver;
    // Major Version Number
    // Assume 2
    uint16_t min_ver;
    // Minor Version Number
    // assume .4
    int32_t timez_offset;
    // GMT to Local time zone
    uint32_t time_accuracy;
    // Length of time accuracy
    uint32_t max_length;
    // Max. Len. of pcap capture dev ( assume 65,523)
    uint32_t linklay_type;
    // link-layer head type (ethernet)
}global;

// PCAP Packet Header - 16B
struct packet{
    uint32_t timestamp;
    uint32_t microseconds;
    uint32_t saved_size;
    // size in bytes in file
    uint32_t live_size;
    // data-stream size when captured
}packet;

// Ethernet Header - 14B
struct ethernet{
    uint32_t dest;
    uint32_t src;
    uint32_t butt;
    // 08 00 = IPv4
}ethernet;

struct IPv4{
    unsigned int ip_ver;
    // IPv4 - 0b0100; IPv6 - 0b0110
    //	unsigned int ihl : 4;
    // IP Header Length 4 bits min 5 = 20 bytes
    unsigned int type_service;
    // Default is 00
    uint16_t packet_length;
    // MAXIMUM size 1500B
    // length of packet (including header and data)
    uint16_t IP_id;
    uint16_t flags;
    uint16_t offset;
    uint16_t ttl;
    uint16_t protocol;
    // 11 = UDP
    uint16_t chksum;
    uint32_t srce_ip;
    uint32_t dest_ip;
}IPv4;

// UDP Header
struct UDP{
    uint16_t srce_pt;
    uint16_t dest_pt;
    uint16_t length;
    uint16_t chksum;
}udp_frame;


#endif /* packet_h */
