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

    uint8_t combined[sizeof(struct udphdr) + sizeof(buf)];

    unsigned char key[32];

    for (size_t i = 0; i < sizeof(key_pairs); i++)
    {
        if (stream_id == key_pairs[i].stream_id){
            memcpy(key, key_pairs[i].key, 32);
            break;
        }
    }
    
    

}

struct stream_key {
    uint64_t stream_id;
    unsigned char key[32]
};

struct stream_key key_pairs[500];
