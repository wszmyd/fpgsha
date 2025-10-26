#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <stdint.h>

#define DIGEST_LEN 64
#define EXPECTED_HEX_LEN 128

void fpgsha512(const uint8_t *msg, uint64_t msg_len, uint8_t digest[DIGEST_LEN]);

static std::string to_hex(const uint8_t *d, size_t n)
{
    static const char *hexd = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
        out[2 * i + 0] = hexd[(d[i] >> 4) & 0xF];
        out[2 * i + 1] = hexd[(d[i] >> 0) & 0xF];
    }
    return out;
}

struct TV
{
    const char *name;
    std::vector<uint8_t> msg;
    const char *expected_hex;
};

static std::vector<uint8_t> repeat(uint8_t b, size_t n) { return std::vector<uint8_t>(n, b); }
static std::vector<uint8_t> seq(uint8_t start, uint8_t end_incl)
{
    std::vector<uint8_t> v;
    v.reserve((size_t)end_incl - (size_t)start + 1);
    for (uint32_t x = start; x <= end_incl; ++x)
        v.push_back((uint8_t)x);
    return v;
}

int main()
{
    std::vector<TV> tests = {
        {"empty-string", {}, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                             "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
        {"abc", {'a', 'b', 'c'}, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                                 "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},

        {"448-bit NIST vector",
         {'a', 'b', 'c', 'd', 'b', 'c', 'd', 'e', 'c', 'd', 'e', 'f', 'd', 'e', 'f', 'g', 'e', 'f', 'g', 'h',
          'f', 'g', 'h', 'i', 'g', 'h', 'i', 'j', 'h', 'i', 'j', 'k', 'i', 'j', 'k', 'l', 'j', 'k', 'l', 'm',
          'k', 'l', 'm', 'n', 'l', 'm', 'n', 'o', 'm', 'n', 'o', 'p', 'n', 'o', 'p', 'q'},
         "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
         "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"},

        {"896-bit NIST vector",
         {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'c', 'd', 'e', 'f',
          'g', 'h', 'i', 'j', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
          'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'h', 'i', 'j', 'k',
          'l', 'm', 'n', 'o', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
          'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 'm', 'n', 'o', 'p',
          'q', 'r', 's', 't', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u'},
         "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
         "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},

        {"million-'a'", repeat('a', 1000000),
         "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
         "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"},

        {"quick-fox",
         {'T', 'h', 'e', ' ', 'q', 'u', 'i', 'c', 'k', ' ', 'b', 'r', 'o', 'w', 'n', ' ', 'f', 'o', 'x', ' ',
          'j', 'u', 'm', 'p', 's', ' ', 'o', 'v', 'e', 'r', ' ', 't', 'h', 'e', ' ', 'l', 'a', 'z', 'y', ' ',
          'd', 'o', 'g'},
         "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64"
         "2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"},
        {"quick-fox-dot",
         {'T', 'h', 'e', ' ', 'q', 'u', 'i', 'c', 'k', ' ', 'b', 'r', 'o', 'w', 'n', ' ', 'f', 'o', 'x', ' ',
          'j', 'u', 'm', 'p', 's', ' ', 'o', 'v', 'e', 'r', ' ', 't', 'h', 'e', ' ', 'l', 'a', 'z', 'y', ' ',
          'd', 'o', 'g', '.'},
         "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bb"
         "c6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed"},

        {"55*a", repeat('a', 55),
         "b0220c772cbf6c1822e2cb38a437d0e1d58772417a4bbb21c961364f8b6143e0"
         "5aa6316dca8d1d7b19e16448419076395f6086cb55101fbd6d5497b148e1745f"},
        {"56*a", repeat('a', 56),
         "962b64aae357d2a4fee3ded8b539bdc9d325081822b0bfc55583133aab44f18b"
         "afe11d72a7ae16c79ce2ba620ae2242d5144809161945f1367f41b3972e26e04"},
        {"64*a", repeat('a', 64),
         "01d35c10c6c38c2dcf48f7eebb3235fb5ad74a65ec4cd016e2354c637a8fb49b"
         "695ef3c1d6f7ae4cd74d78cc9c9bcac9d4f23a73019998a7f73038a5c9b2dbde"},

        {"single-00", std::vector<uint8_t>{0x00},
         "b8244d028981d693af7b456af8efa4cad63d282e19ff14942c246e50d9351d22"
         "704a802a71c3580b6370de4ceb293c324a8423342557d4e5c38438f0e36910ee"},

        {"seq-01..FF", seq(0x01, 0xFF),
         "8c4805f9697a04db5b3e62b70d6c80b836575b8cf47430e1cbb3e38b0627a7f2"
         "94c8a749a0b5f5aa5297a3c24d8290a7941b2ad19b5bfd85ba3108a08408ce45"},

        {"hello-world", {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'}, "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f"
                                                                                 "989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"},
    };

    int passed = 0;
    for (const auto &tv : tests)
    {
        uint8_t dig[DIGEST_LEN] = {0};
        fpgsha512(tv.msg.data(), (uint64_t)tv.msg.size(), dig);
        std::string got = to_hex(dig, DIGEST_LEN);

        bool ok = (std::strlen(tv.expected_hex) == EXPECTED_HEX_LEN) && (got == tv.expected_hex);
        if (ok)
            ++passed;

        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", tv.name);
        if (!ok)
        {
            std::printf("  exp: %s\n", tv.expected_hex);
            std::printf("  got: %s\n", got.c_str());
        }
    }
    std::printf("\nSummary: %d/%zu tests passed\n", passed, tests.size());
    return (passed == (int)tests.size()) ? 0 : 1;
}
