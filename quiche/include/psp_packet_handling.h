#ifndef PSP_PACKET_HANDLING_H
#define PSP_PACKET_HANDLING_H

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <quiche.h>
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
#include <sqlite3.h>

// Need: constants, structs, and functions for packet handling

struct psphdr;

uint32_t counter_one;
uint32_t counter_two;
uint32_t label;
uint32_t length;

unsigned char *psp_key_derivation(unsigned char *buf, uint32_t spi);
ssize_t quiche_encrypt_psp(uint8_t *dst, uint8_t *src, size_t pkt_len, struct sockaddr_in socket, uint16_t src_port, uint64_t stream_id);
ssize_t quiche_decrypt_psp(uint8_t *dst, uint8_t *src, size_t pkt_len, uint64_t stream);

#endif