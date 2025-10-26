#include <ap_int.h>
#include <hls_stream.h>
#include <stdint.h>

static inline ap_uint<64> ROTR64(ap_uint<64> x, unsigned n) { return (x >> n) | (x << (64 - n)); }
static inline ap_uint<64> SHR64(ap_uint<64> x, unsigned n) { return (x >> n); }

static inline ap_uint<64> Ch(ap_uint<64> x, ap_uint<64> y, ap_uint<64> z) { return (x & y) ^ (~x & z); }
static inline ap_uint<64> Maj(ap_uint<64> x, ap_uint<64> y, ap_uint<64> z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline ap_uint<64> SIGMA0(ap_uint<64> x) { return ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39); }
static inline ap_uint<64> SIGMA1(ap_uint<64> x) { return ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41); }
static inline ap_uint<64> sigma0(ap_uint<64> x) { return ROTR64(x, 1) ^ ROTR64(x, 8) ^ SHR64(x, 7); }
static inline ap_uint<64> sigma1(ap_uint<64> x) { return ROTR64(x, 19) ^ ROTR64(x, 61) ^ SHR64(x, 6); }

static const ap_uint<64> K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static const int MAX_MSG_SIZE = 1 << 20;

void fpgsha512(const uint8_t *msg, uint64_t msg_len, uint8_t digest[64])
{
#pragma HLS INTERFACE m_axi port = msg offset = slave bundle = gmem0 depth = MAX_MSG_SIZE max_read_burst_length = 64 num_read_outstanding = 4
#pragma HLS INTERFACE m_axi port = digest offset = slave bundle = gmem1 depth = 64 max_write_burst_length = 32 num_write_outstanding = 2
#pragma HLS INTERFACE s_axilite port = msg_len
#pragma HLS INTERFACE s_axilite port = return

    if (msg_len > (uint64_t)MAX_MSG_SIZE)
    {
        msg_len = MAX_MSG_SIZE;
    }

    ap_uint<64> H[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

    uint64_t processed = 0;
    bool finished = false;

    while (!finished)
    {
#pragma HLS LOOP_FLATTEN off

        ap_uint<8> block[128];

        for (int i = 0; i < 128; ++i)
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

        bool place_len = (processed + 128 > msg_len) && ((processed + 128 - msg_len) >= 17);

        if (place_len)
        {
            uint64_t bit_len_low = msg_len * 8ULL;
            for (int j = 0; j < 8; ++j)
            {
                block[112 + j] = 0x00;
            }
            for (int j = 0; j < 8; ++j)
            {
                block[120 + j] = (ap_uint<8>)((bit_len_low >> (56 - 8 * j)) & 0xFF);
            }
            finished = true;
        }

        ap_uint<64> W[80];

        for (int t = 0; t < 16; ++t)
        {
            ap_uint<64> w = ((ap_uint<64>)block[8 * t + 0] << 56) |
                            ((ap_uint<64>)block[8 * t + 1] << 48) |
                            ((ap_uint<64>)block[8 * t + 2] << 40) |
                            ((ap_uint<64>)block[8 * t + 3] << 32) |
                            ((ap_uint<64>)block[8 * t + 4] << 24) |
                            ((ap_uint<64>)block[8 * t + 5] << 16) |
                            ((ap_uint<64>)block[8 * t + 6] << 8) |
                            ((ap_uint<64>)block[8 * t + 7] << 0);
            W[t] = w;
        }
        for (int t = 16; t < 80; ++t)
        {
            W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
        }

        ap_uint<64> a = H[0], b = H[1], c = H[2], d = H[3];
        ap_uint<64> e = H[4], f = H[5], g = H[6], h = H[7];

        for (int t = 0; t < 80; ++t)
        {
#pragma HLS PIPELINE II = 2
            ap_uint<64> T1 = h + SIGMA1(e) + Ch(e, f, g) + K[t] + W[t];
            ap_uint<64> T2 = SIGMA0(a) + Maj(a, b, c);

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

        processed += 128;

        if (!finished && processed >= msg_len)
        {
            for (int i = 0; i < 128; ++i)
                block[i] = 0x00;

            if ((msg_len & 127ULL) == 0ULL)
            {
                block[0] = 0x80;
            }

            uint64_t bit_len_low = msg_len * 8ULL;
            for (int j = 0; j < 8; ++j)
                block[112 + j] = 0x00;
            for (int j = 0; j < 8; ++j)
                block[120 + j] = (ap_uint<8>)((bit_len_low >> (56 - 8 * j)) & 0xFF);

            for (int t = 0; t < 16; ++t)
            {
                ap_uint<64> w = ((ap_uint<64>)block[8 * t + 0] << 56) |
                                ((ap_uint<64>)block[8 * t + 1] << 48) |
                                ((ap_uint<64>)block[8 * t + 2] << 40) |
                                ((ap_uint<64>)block[8 * t + 3] << 32) |
                                ((ap_uint<64>)block[8 * t + 4] << 24) |
                                ((ap_uint<64>)block[8 * t + 5] << 16) |
                                ((ap_uint<64>)block[8 * t + 6] << 8) |
                                ((ap_uint<64>)block[8 * t + 7] << 0);
                W[t] = w;
            }
            for (int t = 16; t < 80; ++t)
            {
                W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
            }

            a = H[0];
            b = H[1];
            c = H[2];
            d = H[3];
            e = H[4];
            f = H[5];
            g = H[6];
            h = H[7];

            for (int t = 0; t < 80; ++t)
            {
#pragma HLS PIPELINE II = 2
                ap_uint<64> T1 = h + SIGMA1(e) + Ch(e, f, g) + K[t] + W[t];
                ap_uint<64> T2 = SIGMA0(a) + Maj(a, b, c);
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

    for (int i = 0; i < 8; ++i)
    {
        ap_uint<64> w = H[i];
        for (int b = 0; b < 8; ++b)
        {
            digest[8 * i + b] = (uint8_t)((w >> (56 - 8 * b)) & 0xFF);
        }
    }
}
