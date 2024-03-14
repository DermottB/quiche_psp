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

ssize_t quiche_encrypt_psp(uint8_t *buf, struct sockaddr_in socket, uint16_t src_port, uint32_t spi){
    struct udphdr inner_header;
    inner_header.uh_dport = socket.sin_port;
    inner_header.uh_sport = htons(src_port);
    inner_header.uh_ulen = sizeof(inner_header) + sizeof(buf);


    unsigned char combined[sizeof(inner_header) + sizeof(buf)];
    memcpy(combined, &inner_header, sizeof(inner_header));
    memcpy(combined + sizeof(inner_header), buf, sizeof(buf));


    AES_KEY key[32];

    bool key_in = false;

    for (size_t i = 0; i < sizeof(key_pairs); i++)
    {
        if (spi == key_pairs[i].stream_id){
            memcpy(key, key_pairs[i].key, 32);
            key_in = true;
            break;
        }
    }

    unsigned char payload[sizeof(combined)];

    unsigned char iv[64];

    RAND_bytes(iv, 64);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv);

    EVP_EncryptUpdate(ctx, payload, sizeof(payload), combined, sizeof(combined));

    EVP_EncryptFinal(ctx, payload, sizeof(payload));

    EVP_CIPHER_CTX_free(ctx);

    struct psphdr header;

    header.next_header = 17;
    header.reserved = 0;
    header.offset = 0;
    header.sample = 0;
    header.drop = 0;
    header.version = 1;
    header.virtual = 0;
    header.iv = iv;


    struct psptrail trailer;

    unsigned char *psp_packet[sizeof(payload) + sizeof(struct psphdr) + sizeof(struct psptrail)];
    memcpy(psp_packet, &header, sizeof(header));
    memcpy(psp_packet + sizeof(header), payload, sizeof(payload));

    trailer.checksum = SHA256(psp_packet, sizeof(psp_packet), NULL);

    memcpy(psp_packet + sizeof(header) + sizeof(payload), &trailer, sizeof(trailer));


}

struct stream_key {
    uint64_t stream_id;
    unsigned char key[32]
};

struct stream_key key_pairs[50];

struct psphdr {
    uint8_t next_header;
    uint8_t hdr_ext_len;
    unsigned reserved: 2;
    unsigned offset: 6;
    unsigned sample: 1;
    unsigned drop: 1;
    unsigned version: 4;
    unsigned virtual: 1;
    uint32_t spi;
    uint64_t iv;
};

struct psptrail {
    __uint128_t checksum;
};