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
#include <sqlite3.h>

//TODO: Add connection to database to record PSP packets
//TODO: Add comments

ssize_t quiche_encrypt_psp(uint8_t *dst, uint8_t *src, struct sockaddr_in socket, uint16_t src_port, uint64_t stream_id){
    sqlite3 *db;
    
    if (!sqlite3_open("/Users/dermottboylan/Desktop/Project/DermottsEyesOnly.db", &db)){
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    char *sql;
    sqlite3_stmt *stmt;

    sql = "SELECT SPI, ENC_KEY FROM SECURITY_ASSOCIATIONS WHERE STREAM = ?";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK){
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    if(sqlite3_bind_int(stmt, 1, stream_id) != SQLITE_OK){
        fprintf(stderr, "Failed to bind parameter: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    uint32_t spi;
    unsigned char key[32];

    if(sqlite3_step(stmt) == SQLITE_ROW){
        uint32_t spi = sqlite3_column_int(stmt, 0);
        memcpy(key, sqlite3_column_text(stmt, 1), sizeof(key));
    } else {
        fprintf(stderr, "No SPI or encryption key found for stream: %lu\n", stream_id);
        return -1;
    }

    struct udphdr inner_header;
    inner_header.uh_dport = socket.sin_port;
    inner_header.uh_sport = htons(src_port);
    inner_header.uh_ulen = sizeof(inner_header) + sizeof(src);


    unsigned char combined[sizeof(inner_header) + sizeof(src)];
    memcpy(combined, &inner_header, sizeof(inner_header));
    memcpy(combined + sizeof(inner_header), src, sizeof(src));


    AES_KEY aes_key[32];
    if(AES_set_encrypt_key(key, 256, aes_key) != 0){
        fprintf(stderr, "Failed to set AES key\n");
        return -1;
    }

    unsigned char payload[sizeof(combined)];

    unsigned char iv[64];

    RAND_bytes(iv, 64);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv);

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
    memcpy(dst, &header, sizeof(header));
    memcpy(dst + sizeof(header), payload, sizeof(payload));

    memcpy(trailer.checksum, SHA256(psp_packet, sizeof(psp_packet), NULL), sizeof(trailer.checksum));

    memcpy(dst + sizeof(header) + sizeof(payload), &trailer, sizeof(trailer));

    return sizeof(dst);
}


ssize_t quiche_decrypt_psp(uint8_t *dst, uint8_t *src, uint32_t){
    struct psphdr header;
    memcpy(&header, src, sizeof(header));

    unsigned char payload[sizeof(src) - sizeof(header) - sizeof(struct psptrail)];
    memcpy(payload, src + sizeof(header), sizeof(payload));

    struct psptrail trailer;
    memcpy(&trailer, src + sizeof(header) + sizeof(payload), sizeof(trailer));

    unsigned char *psp_packet[sizeof(payload) + sizeof(struct psphdr) + sizeof(struct psptrail)];
    memcpy(psp_packet, &header, sizeof(header));
    memcpy(psp_packet + sizeof(header), payload, sizeof(payload));

    if(memcmp(trailer.checksum, SHA256(psp_packet, sizeof(psp_packet), NULL), sizeof(trailer.checksum)) != 0){
        return -1;
    }

    AES_KEY key[32];

    unsigned char iv[64];
    memcpy(iv, header.iv, sizeof(iv));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv);

    EVP_DecryptUpdate(ctx, dst, sizeof(dst), payload, sizeof(payload));

    EVP_DecryptFinal(ctx, dst, sizeof(dst));

    EVP_CIPHER_CTX_free(ctx);

    return sizeof(dst);

}


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