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
#include <openssl/err.h>

#include "quiche_psp.h"

struct master_key keys[2] = {
        {
            .key = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20},
            .active = true
        },
        {
            .key = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                    0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40},
            .active = false
        }
    };

uint32_t counter_one = 0x00000001;
uint32_t counter_two = 0x00000002;
uint32_t label = 0x50763000;
uint32_t length = 0x00000100;

ssize_t psp_key_derivation(unsigned char *buf, uint32_t spi){
    // Get the first bit of the SPI
    unsigned char spi_bit = spi & 0x80000000;

    unsigned char key_dest[32];
    uint8_t *master_key = key_dest;
    memcpy(master_key, &keys[spi_bit].key, 32);

    __uint128_t hex_bytes_one = ((__uint128_t) counter_one << 96) | ((__uint128_t) label << 64) | ((__uint128_t) spi << 32) | ((__uint128_t) length);
    __uint128_t hex_bytes_two = ((__uint128_t) counter_two << 96) | ((__uint128_t) label << 64) | ((__uint128_t) spi << 32) | ((__uint128_t) length);

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if(!libctx){
        fprintf(stderr, "Failed to create libctx\n");
        return -1;
    }
    
    EVP_MAC *mac = EVP_MAC_fetch(libctx, "CMAC", NULL);
    
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if(!ctx){
        fprintf(stderr, "Failed to create CMAC context\n");
        return -1;
    }

    OSSL_PARAM params[4], * p = params;
    char cipher_name[] = "AES-256-CBC";

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher_name, sizeof(cipher_name));
    *p = OSSL_PARAM_construct_end(); 

    if(EVP_MAC_init(ctx, master_key, 32, params) != 1){
        fprintf(stderr, "Failed to initialise CMAC context\n");
        BIO *bio = BIO_new_fp(stderr, BIO_NOCLOSE);
        ERR_print_errors(bio);
        return -1;
    }

    if(EVP_MAC_update(ctx, master_key, sizeof(master_key)) != 1){
        fprintf(stderr, "Failed to update CMAC context\n");
        return -1;
    }
    unsigned char cmac_one[16];
    unsigned char cmac_two[16];

    if(EVP_MAC_final(ctx, cmac_one, NULL, sizeof(cmac_one)) != 1){
        fprintf(stderr, "Failed to finalise CMAC context\n");
        return -1;
    }

    if(EVP_MAC_final(ctx, cmac_two, NULL, sizeof(cmac_two)) != 1){
        fprintf(stderr, "Failed to finalise CMAC context\n");
        return -1;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    memcpy(buf, cmac_one, sizeof(cmac_one));
    memcpy(buf + sizeof(cmac_one), cmac_two, sizeof(cmac_two));

    return 32;
}

ssize_t quiche_encrypt_psp(uint8_t *dst, uint8_t *src, size_t pkt_len, struct sockaddr_in *local, struct sockaddr_in *peer, struct security_association *sa){

    // Create the inner header
    struct udphdr inner_header;
    inner_header.uh_dport = peer->sin_port;
    inner_header.uh_sport = local->sin_port;
    inner_header.uh_ulen = sizeof(inner_header) + pkt_len;


    // Combine the inner header and the payload
    unsigned char payload[sizeof(inner_header) + pkt_len];
    memcpy(payload, &inner_header, sizeof(inner_header));
    memcpy(payload + sizeof(inner_header), src, pkt_len);

    int payload_len = sizeof(inner_header) + pkt_len;
    int *pl = &payload_len;

    unsigned char iv[8];

    RAND_bytes(iv, 8);

    uint32_t spi = sa->spi;
    unsigned char key[32];
    uint8_t *keyptr = key;
    memcpy(keyptr, &sa->enc_key, 32);

    unsigned char iv_spi[sizeof(iv) + sizeof(spi)];
    memcpy(iv_spi, iv, sizeof(iv));
    memcpy(iv_spi + sizeof(iv), &spi, sizeof(spi));

    struct psphdr header;
    uint8_t psp_header[16] = {0};

    unsigned char tag[16];

    unsigned char *psp_packet[sizeof(payload) + sizeof(psp_header) + sizeof(tag)];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!ctx){
        fprintf(stderr, "Failed to create EVP context\n");
        goto enc_error;
    }

    if(EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv_spi) != 1){
        fprintf(stderr, "Failed to initialise EVP context\n");
        goto enc_error;
    }

    if(EVP_EncryptUpdate(ctx, payload, pl, payload, sizeof(inner_header) + pkt_len) != 1){
        fprintf(stderr, "Failed to update EVP context\n");
        goto enc_error;
    }

    if(EVP_EncryptFinal(ctx, payload, pl) != 1){
        fprintf(stderr, "Failed to finalise EVP context\n");
        goto enc_error;
    }

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1){
        fprintf(stderr, "Failed to get tag\n");
        goto enc_error;
    }

    EVP_CIPHER_CTX_free(ctx);

    header.next_header = 0x0011;
    header.hdr_ext_len = 0x0000;
    header.reserved = 0x0;
    header.offset = 0x0;
    header.sample = 0x0;
    header.drop = 0x0;
    header.version = 0x1;
    header.vcookie = 0x0;
    header.padding = 0x1;
    header.spi = spi;
    header.iv = (uint64_t) iv;

    psp_header[0] = header.next_header;
    psp_header[1] = header.hdr_ext_len;
    psp_header[2] = header.reserved << 6 | header.offset;
    psp_header[3] = header.sample << 7 | header.drop << 6 | header.version << 4 | header.vcookie << 1 | header.padding;
    psp_header[4] = header.spi >> 24;
    psp_header[5] = header.spi >> 16;
    psp_header[6] = header.spi >> 8;
    psp_header[7] = header.spi;
    psp_header[8] = header.iv >> 56;
    psp_header[9] = header.iv >> 48;
    psp_header[10] = header.iv >> 40;
    psp_header[11] = header.iv >> 32;
    psp_header[12] = header.iv >> 24;
    psp_header[13] = header.iv >> 16;
    psp_header[14] = header.iv >> 8;
    psp_header[15] = header.iv;

    memcpy(dst, &psp_header, sizeof(psp_header));
    memcpy(dst + sizeof(psp_header), payload, sizeof(payload));
    memcpy(dst + sizeof(psp_header) + sizeof(payload), tag, sizeof(tag));

    return sizeof(dst);

    enc_error:

        return -1;
}


ssize_t quiche_decrypt_psp(uint8_t *dst, uint8_t *pkt, size_t pkt_len){
    struct psphdr header;
    memcpy(&header, pkt, sizeof(header));

    unsigned char payload[pkt_len - 32];
    memcpy(payload, pkt + sizeof(header), sizeof(payload));

    unsigned char tag[16];
    memcpy(&tag, pkt + sizeof(header) + sizeof(payload), sizeof(tag));

    unsigned char key[32]; 
    psp_key_derivation(key, header.spi);

    unsigned char iv_spi[sizeof(header.iv) + sizeof(header.spi)];
    memcpy(iv_spi, &header.iv, sizeof(header.iv));
    memcpy(iv_spi + sizeof(header.iv), &header.spi, sizeof(header.spi));

    int dec_len = pkt_len - 32;
    int *p = &dec_len;

    unsigned char udppayload[pkt_len - 32];
    uint8_t *payloadptr = udppayload;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, iv_spi);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

    EVP_DecryptUpdate(ctx, udppayload, p, payloadptr, pkt_len - 32);

    EVP_DecryptFinal(ctx, udppayload, p);

    EVP_CIPHER_CTX_free(ctx);

    struct udphdr udphdr;

    memcpy(dst, payload + sizeof(udphdr), sizeof(udppayload) - sizeof(udphdr));

    return sizeof(udppayload) - sizeof(udphdr);

}
