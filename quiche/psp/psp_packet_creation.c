#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <quiche.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <openssl/aes.h>

ssize_t quiche_encrypt_psp(uint8_t *buf, struct sockaddr_in socket, uint16_t src_port, uint64_t stream_id){
    struct udphdr inner_header;
    inner_header.uh_dport = socket.sin_port;
    inner_header.uh_sport = htons(src_port);
    inner_header.uh_ulen = sizeof(inner_header) + sizeof(buf);


    unsigned char combined[sizeof(inner_header) + sizeof(buf)];
    memcpy(combined, &inner_header, sizeof(inner_header));
    memcpy(combined + sizeof(inner_header), buf, sizeof(buf));


    AES_KEY key[32];

    for (size_t i = 0; i < sizeof(key_pairs); i++)
    {
        if (stream_id == key_pairs[i].stream_id){
            memcpy(key, key_pairs[i].key, 32);
            break;
        }
    }

    unsigned char payload[sizeof(combined)];
    
    AES_encrypt(combined, payload, key);

    struct psphdr header;
    header.poo = 10;

    unsigned char psp_packet[sizeof(payload) + sizeof(struct psphdr)];
    memcpy(psp_packet, &header, sizeof(header));
    memcpy(psp_packet, payload, sizeof(payload));


}

//TODO: Add key pairs to the key_pairs array
struct stream_key {
    uint64_t stream_id;
    unsigned char key[32]
};

//TODO: Dynamically allocate key_pairs
struct stream_key key_pairs[500];


//TODO: Complete PSP header fields
struct psphdr {
    uint16_t poo;
};
