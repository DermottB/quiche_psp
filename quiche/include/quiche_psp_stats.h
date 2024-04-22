#ifndef NGTCP2_PSP_STATS_H
#define NGTCP2_PSP_STATS_H

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ngtcp2/ngtcp2.h>

struct psp_stats {
    uint32_t packets_encrypted;
    uint32_t bytes_encrypted;

    uint32_t packets_decrypted;
    uint32_t bytes_decrypted;
};

#endif