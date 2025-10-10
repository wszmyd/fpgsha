#pragma once
#include <ap_int.h>
#include <hls_stream.h>
#include <stdint.h>

// bit operations
static inline ap_uint<32> ROTR(ap_uint<32> x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static inline ap_uint<32> SHR(ap_uint<32> x, unsigned n) { return (x >> n); }

// sha256 functions
static inline ap_uint<32> Ch(ap_uint<32> x, ap_uint<32> y, ap_uint<32> z) { return (x & y) ^ (~x & z); }
static inline ap_uint<32> Maj(ap_uint<32> x, ap_uint<32> y, ap_uint<32> z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline ap_uint<32> SIGMA0(ap_uint<32> x) { return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22); }
static inline ap_uint<32> SIGMA1(ap_uint<32> x) { return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25); }
static inline ap_uint<32> sigma0(ap_uint<32> x) { return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3); }
static inline ap_uint<32> sigma1(ap_uint<32> x) { return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10); }

// round constants
static const ap_uint<32> K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

void sha256_hls(const uint8_t *msg, uint64_t msg_len, uint8_t digest[32])
{
    // H0
    ap_uint<32> H[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};

    uint64_t processed = 0;
    bool finished = false;
    while (!finished)
    {
        ap_uint<8> block[64];

        // build 512b block, padding
        for (int i = 0; i < 64; ++i)
        {
            uint64_t idx = processed + i;
            if (idx < msg_len)
            {
                block[i] = msg[idx];
            }
            else if (idx == msg_len)
            {
                block[i] = 0x80; // first padding bit
            }
            else
            {
                block[i] = 0x00;
            }
        }

        // if the 64-bit length fits in this block
        bool place_len = (processed + 64 > msg_len) && (processed + 64 - msg_len >= 9);

        if (place_len)
        {
            // write message length in bits (big-endian)
            uint64_t bit_len = msg_len * 8ULL;
            for (int j = 0; j < 8; ++j)
            {
                block[56 + j] = (ap_uint<8>)((bit_len >> (56 - 8 * j)) & 0xFF);
            }
            finished = true;
        }

        // message schedule W[0..63]
        ap_uint<32> W[64];

        for (int t = 0; t < 16; ++t)
        {
            ap_uint<32> w = ((ap_uint<32>)block[4 * t + 0] << 24) |
                            ((ap_uint<32>)block[4 * t + 1] << 16) |
                            ((ap_uint<32>)block[4 * t + 2] << 8) |
                            ((ap_uint<32>)block[4 * t + 3] << 0);
            W[t] = w;
        }
        for (int t = 16; t < 64; ++t)
        {
            W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
        }

        // variables
        ap_uint<32> a = H[0], b = H[1], c = H[2], d = H[3];
        ap_uint<32> e = H[4], f = H[5], g = H[6], h = H[7];

        // main compression loop (64 rounds)
        for (int t = 0; t < 64; ++t)
        {
#pragma HLS PIPELINE II = 1
            ap_uint<32> T1 = h + SIGMA1(e) + Ch(e, f, g) + K[t] + W[t];
            ap_uint<32> T2 = SIGMA0(a) + Maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // Add the compressed chunk to the current hash value
        H[0] = H[0] + a;
        H[1] = H[1] + b;
        H[2] = H[2] + c;
        H[3] = H[3] + d;
        H[4] = H[4] + e;
        H[5] = H[5] + f;
        H[6] = H[6] + g;
        H[7] = H[7] + h;

        processed += 64;

        // second (final) block when length didn't fit above
        if (!finished && processed >= msg_len)
        {
            for (int i = 0; i < 64; ++i)
            {
                block[i] = 0x00;
            }
            if ((msg_len & 63ULL) == 0ULL)
            {
                block[0] = 0x80;
            }
            uint64_t bit_len = msg_len * 8ULL;
            for (int j = 0; j < 8; ++j)
            {
                block[56 + j] = (ap_uint<8>)((bit_len >> (56 - 8 * j)) & 0xFF);
            }

            // rebuild W
            for (int t = 0; t < 16; ++t)
            {
                ap_uint<32> w = ((ap_uint<32>)block[4 * t + 0] << 24) |
                                ((ap_uint<32>)block[4 * t + 1] << 16) |
                                ((ap_uint<32>)block[4 * t + 2] << 8) |
                                ((ap_uint<32>)block[4 * t + 3] << 0);
                W[t] = w;
            }

            for (int t = 16; t < 64; ++t)
            {
                W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
            }

            // rerun 64 rounds
            a = H[0];
            b = H[1];
            c = H[2];
            d = H[3];
            e = H[4];
            f = H[5];
            g = H[6];
            h = H[7];

            for (int t = 0; t < 64; ++t)
            {
#pragma HLS PIPELINE II = 1
                ap_uint<32> T1 = h + SIGMA1(e) + Ch(e, f, g) + K[t] + W[t];
                ap_uint<32> T2 = SIGMA0(a) + Maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }
            H[0] = H[0] + a;
            H[1] = H[1] + b;
            H[2] = H[2] + c;
            H[3] = H[3] + d;
            H[4] = H[4] + e;
            H[5] = H[5] + f;
            H[6] = H[6] + g;
            H[7] = H[7] + h;

            finished = true;
        }
    }

    // output digest (big-endian)
    for (int i = 0; i < 8; ++i)
    {
        ap_uint<32> w = H[i];
        digest[4 * i + 0] = (uint8_t)((w >> 24) & 0xFF);
        digest[4 * i + 1] = (uint8_t)((w >> 16) & 0xFF);
        digest[4 * i + 2] = (uint8_t)((w >> 8) & 0xFF);
        digest[4 * i + 3] = (uint8_t)((w >> 0) & 0xFF);
    }
}
