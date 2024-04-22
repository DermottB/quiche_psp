#ifndef PSP_PACKET_HANDLING_H
#define PSP_PACKET_HANDLING_H

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/cmac.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <quiche.h>

struct psphdr {
    uint8_t next_header;
    uint8_t hdr_ext_len;
    unsigned reserved: 2;
    unsigned offset: 6;
    unsigned sample: 1;
    unsigned drop: 1;
    unsigned version: 4;
    unsigned vcookie: 1;
    unsigned padding: 1;
    uint32_t spi;
    uint64_t iv;
};

struct security_association {
    uint32_t spi;
    bool outbound;
    uint8_t *enc_key;
    quiche_conn *conn;
};

struct master_key {
    unsigned char key[32];
    bool active;
};

uint32_t counter_one;
uint32_t counter_two;
uint32_t label;
uint32_t length;

ssize_t psp_key_derivation(unsigned char *buf, uint32_t spi);
ssize_t quiche_encrypt_psp(uint8_t *dst, uint8_t *src, size_t pkt_len, struct sockaddr_in *local, struct sockaddr_in *peer, struct security_association *sa);
ssize_t quiche_decrypt_psp(uint8_t *dst, uint8_t *pkt, size_t pkt_len);


#endif