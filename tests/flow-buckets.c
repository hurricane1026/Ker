#include "check.h"
#include "eal.h"
#include "runtime/flow.h"
#include "runtime/worker.h"
#include "runtime/memory.h"
#include <errno.h>
#include <string.h>

#define SEED UINT64_C(0x123456789abcdef0)
/* Fixed vectors generated offline using byte serialization and Python integer
 * arithmetic, never by the runtime under test. Array index is expected bucket.
 * Tuple: remote UDP port, complete expected hash. */
static const struct { uint16_t port; uint32_t hash; } vectors[256] = {
    {31, UINT32_C(0x7c63e500)}, /* 0 */
    {56, UINT32_C(0xc6e37d01)}, /* 1 */
    {325, UINT32_C(0x3abc0202)}, /* 2 */
    {17, UINT32_C(0x4fe20103)}, /* 3 */
    {169, UINT32_C(0xccc3b204)}, /* 4 */
    {175, UINT32_C(0xf6c1e505)}, /* 5 */
    {25, UINT32_C(0xb6688006)}, /* 6 */
    {10, UINT32_C(0x969f1a07)}, /* 7 */
    {196, UINT32_C(0x9d4a3808)}, /* 8 */
    {28, UINT32_C(0x47dfa009)}, /* 9 */
    {340, UINT32_C(0xe124d80a)}, /* 10 */
    {97, UINT32_C(0x74f77e0b)}, /* 11 */
    {112, UINT32_C(0x7460cd0c)}, /* 12 */
    {93, UINT32_C(0x951a420d)}, /* 13 */
    {195, UINT32_C(0x68c7900e)}, /* 14 */
    {769, UINT32_C(0xa6c8940f)}, /* 15 */
    {128, UINT32_C(0xe27d3110)}, /* 16 */
    {700, UINT32_C(0x38926011)}, /* 17 */
    {246, UINT32_C(0x761a7512)}, /* 18 */
    {27, UINT32_C(0x39492d13)}, /* 19 */
    {111, UINT32_C(0x183b6b14)}, /* 20 */
    {423, UINT32_C(0xd1252015)}, /* 21 */
    {187, UINT32_C(0xde470916)}, /* 22 */
    {230, UINT32_C(0x9fc7be17)}, /* 23 */
    {78, UINT32_C(0xb676b218)}, /* 24 */
    {59, UINT32_C(0xa1400019)}, /* 25 */
    {252, UINT32_C(0x7a387c1a)}, /* 26 */
    {186, UINT32_C(0x813a541b)}, /* 27 */
    {282, UINT32_C(0x7999c51c)}, /* 28 */
    {190, UINT32_C(0xb5255c1d)}, /* 29 */
    {343, UINT32_C(0x1981871e)}, /* 30 */
    {204, UINT32_C(0xceb5df1f)}, /* 31 */
    {665, UINT32_C(0xc8234b20)}, /* 32 */
    {373, UINT32_C(0xb417d021)}, /* 33 */
    {281, UINT32_C(0xdf986a22)}, /* 34 */
    {464, UINT32_C(0x0a26a623)}, /* 35 */
    {772, UINT32_C(0x12e36424)}, /* 36 */
    {58, UINT32_C(0x6d9b5325)}, /* 37 */
    {24, UINT32_C(0x89a11126)}, /* 38 */
    {155, UINT32_C(0xd9578c27)}, /* 39 */
    {77, UINT32_C(0x349cc328)}, /* 40 */
    {5, UINT32_C(0xefdcc829)}, /* 41 */
    {32, UINT32_C(0xdcd4ed2a)}, /* 42 */
    {70, UINT32_C(0x76876f2b)}, /* 43 */
    {388, UINT32_C(0x1609822c)}, /* 44 */
    {458, UINT32_C(0x2716292d)}, /* 45 */
    {133, UINT32_C(0x2fd8ef2e)}, /* 46 */
    {29, UINT32_C(0x22403e2f)}, /* 47 */
    {8, UINT32_C(0x5c608f30)}, /* 48 */
    {759, UINT32_C(0x2e313e31)}, /* 49 */
    {84, UINT32_C(0xc7dc5232)}, /* 50 */
    {74, UINT32_C(0xa626ad33)}, /* 51 */
    {87, UINT32_C(0x7e976e34)}, /* 52 */
    {76, UINT32_C(0x363c3935)}, /* 53 */
    {49, UINT32_C(0x46124036)}, /* 54 */
    {209, UINT32_C(0xfdac0a37)}, /* 55 */
    {528, UINT32_C(0xe57d3638)}, /* 56 */
    {329, UINT32_C(0x6603c839)}, /* 57 */
    {57, UINT32_C(0x7d7b2e3a)}, /* 58 */
    {217, UINT32_C(0x70cb333b)}, /* 59 */
    {237, UINT32_C(0x6b98ab3c)}, /* 60 */
    {69, UINT32_C(0xb9aa013d)}, /* 61 */
    {447, UINT32_C(0x74265b3e)}, /* 62 */
    {113, UINT32_C(0x6941413f)}, /* 63 */
    {275, UINT32_C(0x54b41240)}, /* 64 */
    {219, UINT32_C(0x5dde5e41)}, /* 65 */
    {142, UINT32_C(0x1c82bc42)}, /* 66 */
    {48, UINT32_C(0x8623e043)}, /* 67 */
    {134, UINT32_C(0x03115344)}, /* 68 */
    {298, UINT32_C(0x5003f645)}, /* 69 */
    {149, UINT32_C(0x098f2746)}, /* 70 */
    {123, UINT32_C(0x50509047)}, /* 71 */
    {139, UINT32_C(0x0f68c548)}, /* 72 */
    {13, UINT32_C(0x0e7ae749)}, /* 73 */
    {22, UINT32_C(0xa9570f4a)}, /* 74 */
    {203, UINT32_C(0xce30bf4b)}, /* 75 */
    {36, UINT32_C(0x11f27f4c)}, /* 76 */
    {167, UINT32_C(0x2e635b4d)}, /* 77 */
    {274, UINT32_C(0x61277e4e)}, /* 78 */
    {243, UINT32_C(0x08667a4f)}, /* 79 */
    {547, UINT32_C(0x4e0f3650)}, /* 80 */
    {82, UINT32_C(0xde853151)}, /* 81 */
    {193, UINT32_C(0x110a9952)}, /* 82 */
    {21, UINT32_C(0x78984c53)}, /* 83 */
    {132, UINT32_C(0xbcfe3c54)}, /* 84 */
    {6, UINT32_C(0x75e4c055)}, /* 85 */
    {163, UINT32_C(0x1088df56)}, /* 86 */
    {176, UINT32_C(0x222aa757)}, /* 87 */
    {356, UINT32_C(0xb2dc5758)}, /* 88 */
    {457, UINT32_C(0x45b7a559)}, /* 89 */
    {23, UINT32_C(0x9ce0925a)}, /* 90 */
    {218, UINT32_C(0xe62acc5b)}, /* 91 */
    {67, UINT32_C(0xfc6a7d5c)}, /* 92 */
    {20, UINT32_C(0x67ae205d)}, /* 93 */
    {262, UINT32_C(0xf9c8d75e)}, /* 94 */
    {905, UINT32_C(0xfa59c55f)}, /* 95 */
    {15, UINT32_C(0xd3119b60)}, /* 96 */
    {39, UINT32_C(0x1c6bd961)}, /* 97 */
    {234, UINT32_C(0x93dd3d62)}, /* 98 */
    {45, UINT32_C(0x1d45e563)}, /* 99 */
    {309, UINT32_C(0x9e5dbe64)}, /* 100 */
    {633, UINT32_C(0x638e8965)}, /* 101 */
    {279, UINT32_C(0xf027e566)}, /* 102 */
    {1, UINT32_C(0x694dc967)}, /* 103 */
    {198, UINT32_C(0x81ba7468)}, /* 104 */
    {107, UINT32_C(0xd4d03869)}, /* 105 */
    {477, UINT32_C(0x36a48d6a)}, /* 106 */
    {47, UINT32_C(0x4fe6596b)}, /* 107 */
    {18, UINT32_C(0x7b066f6c)}, /* 108 */
    {631, UINT32_C(0xb282df6d)}, /* 109 */
    {591, UINT32_C(0xfa70d66e)}, /* 110 */
    {339, UINT32_C(0x6d514a6f)}, /* 111 */
    {174, UINT32_C(0x1aaa6170)}, /* 112 */
    {37, UINT32_C(0x9fad5471)}, /* 113 */
    {168, UINT32_C(0x03308d72)}, /* 114 */
    {214, UINT32_C(0xd2066c73)}, /* 115 */
    {290, UINT32_C(0x2b28b974)}, /* 116 */
    {52, UINT32_C(0x6833bf75)}, /* 117 */
    {151, UINT32_C(0x217bcc76)}, /* 118 */
    {64, UINT32_C(0x12408b77)}, /* 119 */
    {231, UINT32_C(0x3a40b078)}, /* 120 */
    {735, UINT32_C(0xa796cd79)}, /* 121 */
    {73, UINT32_C(0xee71a87a)}, /* 122 */
    {129, UINT32_C(0xc2cc2a7b)}, /* 123 */
    {192, UINT32_C(0xf6fb6b7c)}, /* 124 */
    {165, UINT32_C(0x3a99ce7d)}, /* 125 */
    {4, UINT32_C(0xf2c78e7e)}, /* 126 */
    {171, UINT32_C(0x534b717f)}, /* 127 */
    {125, UINT32_C(0x58062f80)}, /* 128 */
    {121, UINT32_C(0x6b755481)}, /* 129 */
    {278, UINT32_C(0xfd5ee482)}, /* 130 */
    {33, UINT32_C(0x6e2f4683)}, /* 131 */
    {308, UINT32_C(0xbae34584)}, /* 132 */
    {446, UINT32_C(0x9b8f1785)}, /* 133 */
    {156, UINT32_C(0xd64ffb86)}, /* 134 */
    {138, UINT32_C(0xae6e4887)}, /* 135 */
    {172, UINT32_C(0x81ede688)}, /* 136 */
    {30, UINT32_C(0xdae65989)}, /* 137 */
    {61, UINT32_C(0x5ac71b8a)}, /* 138 */
    {242, UINT32_C(0x9afc5a8b)}, /* 139 */
    {613, UINT32_C(0x05ab278c)}, /* 140 */
    {53, UINT32_C(0x82ecc08d)}, /* 141 */
    {501, UINT32_C(0xe653a38e)}, /* 142 */
    {0, UINT32_C(0x0411f08f)}, /* 143 */
    {62, UINT32_C(0x817bcf90)}, /* 144 */
    {42, UINT32_C(0x28956c91)}, /* 145 */
    {66, UINT32_C(0x93629992)}, /* 146 */
    {114, UINT32_C(0x2013e793)}, /* 147 */
    {256, UINT32_C(0x3ab25894)}, /* 148 */
    {643, UINT32_C(0x9753b895)}, /* 149 */
    {109, UINT32_C(0x7e4f3696)}, /* 150 */
    {417, UINT32_C(0x40f71997)}, /* 151 */
    {135, UINT32_C(0xc9dfc098)}, /* 152 */
    {104, UINT32_C(0x21d0a399)}, /* 153 */
    {797, UINT32_C(0xc4ac269a)}, /* 154 */
    {35, UINT32_C(0x5918319b)}, /* 155 */
    {319, UINT32_C(0xd844c79c)}, /* 156 */
    {63, UINT32_C(0x29350f9d)}, /* 157 */
    {81, UINT32_C(0x0b437d9e)}, /* 158 */
    {503, UINT32_C(0xea83969f)}, /* 159 */
    {303, UINT32_C(0x2ceb1fa0)}, /* 160 */
    {257, UINT32_C(0xe7416fa1)}, /* 161 */
    {398, UINT32_C(0x4fd265a2)}, /* 162 */
    {598, UINT32_C(0xe3bfdea3)}, /* 163 */
    {3, UINT32_C(0x07e52ca4)}, /* 164 */
    {288, UINT32_C(0xf5e959a5)}, /* 165 */
    {72, UINT32_C(0xecd252a6)}, /* 166 */
    {463, UINT32_C(0x0990c0a7)}, /* 167 */
    {311, UINT32_C(0x7f147da8)}, /* 168 */
    {108, UINT32_C(0x4c51b3a9)}, /* 169 */
    {40, UINT32_C(0x0fe913aa)}, /* 170 */
    {289, UINT32_C(0x5db146ab)}, /* 171 */
    {492, UINT32_C(0xfcf57dac)}, /* 172 */
    {11, UINT32_C(0xeabdcaad)}, /* 173 */
    {189, UINT32_C(0x083b0fae)}, /* 174 */
    {488, UINT32_C(0x9ebd71af)}, /* 175 */
    {88, UINT32_C(0xb4b5beb0)}, /* 176 */
    {117, UINT32_C(0xce4db2b1)}, /* 177 */
    {99, UINT32_C(0x2539deb2)}, /* 178 */
    {14, UINT32_C(0xf43f2cb3)}, /* 179 */
    {409, UINT32_C(0x5abc42b4)}, /* 180 */
    {44, UINT32_C(0xd3d54eb5)}, /* 181 */
    {630, UINT32_C(0x70859cb6)}, /* 182 */
    {330, UINT32_C(0x1e776ab7)}, /* 183 */
    {344, UINT32_C(0x4fb12ab8)}, /* 184 */
    {150, UINT32_C(0x294a4eb9)}, /* 185 */
    {787, UINT32_C(0xe960faba)}, /* 186 */
    {295, UINT32_C(0x1611c7bb)}, /* 187 */
    {465, UINT32_C(0x087739bc)}, /* 188 */
    {261, UINT32_C(0xcb9906bd)}, /* 189 */
    {400, UINT32_C(0xb38ce1be)}, /* 190 */
    {689, UINT32_C(0xacf6eebf)}, /* 191 */
    {38, UINT32_C(0xb1320dc0)}, /* 192 */
    {105, UINT32_C(0x23fc59c1)}, /* 193 */
    {532, UINT32_C(0xe67fa8c2)}, /* 194 */
    {898, UINT32_C(0x5c0ceac3)}, /* 195 */
    {661, UINT32_C(0x18592ec4)}, /* 196 */
    {312, UINT32_C(0xcc0513c5)}, /* 197 */
    {285, UINT32_C(0x857436c6)}, /* 198 */
    {201, UINT32_C(0x4275bbc7)}, /* 199 */
    {68, UINT32_C(0x6cb850c8)}, /* 200 */
    {851, UINT32_C(0x778bcec9)}, /* 201 */
    {127, UINT32_C(0xbc1455ca)}, /* 202 */
    {529, UINT32_C(0xeaf868cb)}, /* 203 */
    {227, UINT32_C(0xd19ce5cc)}, /* 204 */
    {9, UINT32_C(0x4e1070cd)}, /* 205 */
    {241, UINT32_C(0x09eec1ce)}, /* 206 */
    {614, UINT32_C(0x266927cf)}, /* 207 */
    {321, UINT32_C(0x8fbdddd0)}, /* 208 */
    {106, UINT32_C(0x2ad38ad1)}, /* 209 */
    {34, UINT32_C(0x838bb3d2)}, /* 210 */
    {871, UINT32_C(0x1f005dd3)}, /* 211 */
    {51, UINT32_C(0xbb50f0d4)}, /* 212 */
    {98, UINT32_C(0x7be670d5)}, /* 213 */
    {404, UINT32_C(0xe24263d6)}, /* 214 */
    {120, UINT32_C(0xb2f78ed7)}, /* 215 */
    {368, UINT32_C(0xed21aed8)}, /* 216 */
    {326, UINT32_C(0x4384cdd9)}, /* 217 */
    {145, UINT32_C(0x7bc6fbda)}, /* 218 */
    {827, UINT32_C(0x9fcfd5db)}, /* 219 */
    {514, UINT32_C(0xbf2460dc)}, /* 220 */
    {367, UINT32_C(0x67a1c4dd)}, /* 221 */
    {130, UINT32_C(0x36426fde)}, /* 222 */
    {115, UINT32_C(0xf854aedf)}, /* 223 */
    {164, UINT32_C(0x1213a1e0)}, /* 224 */
    {41, UINT32_C(0xc9d759e1)}, /* 225 */
    {674, UINT32_C(0x488ca4e2)}, /* 226 */
    {273, UINT32_C(0xb86e18e3)}, /* 227 */
    {71, UINT32_C(0x8fa1dae4)}, /* 228 */
    {100, UINT32_C(0xad631fe5)}, /* 229 */
    {122, UINT32_C(0x0a625ee6)}, /* 230 */
    {101, UINT32_C(0xb5030fe7)}, /* 231 */
    {250, UINT32_C(0xfb9f7ce8)}, /* 232 */
    {268, UINT32_C(0xec4409e9)}, /* 233 */
    {96, UINT32_C(0x8a5336ea)}, /* 234 */
    {110, UINT32_C(0x649112eb)}, /* 235 */
    {511, UINT32_C(0x24b653ec)}, /* 236 */
    {12, UINT32_C(0x490938ed)}, /* 237 */
    {1671, UINT32_C(0x90911eee)}, /* 238 */
    {442, UINT32_C(0x53024bef)}, /* 239 */
    {94, UINT32_C(0xdb3a91f0)}, /* 240 */
    {2, UINT32_C(0xf8f976f1)}, /* 241 */
    {19, UINT32_C(0x40ab14f2)}, /* 242 */
    {270, UINT32_C(0xe069faf3)}, /* 243 */
    {225, UINT32_C(0x409983f4)}, /* 244 */
    {159, UINT32_C(0xe68f13f5)}, /* 245 */
    {684, UINT32_C(0x2a233af6)}, /* 246 */
    {79, UINT32_C(0x465211f7)}, /* 247 */
    {55, UINT32_C(0xb41db0f8)}, /* 248 */
    {315, UINT32_C(0x906016f9)}, /* 249 */
    {90, UINT32_C(0x2c2a96fa)}, /* 250 */
    {559, UINT32_C(0xa2e6eefb)}, /* 251 */
    {7, UINT32_C(0x05af6bfc)}, /* 252 */
    {75, UINT32_C(0x11d600fd)}, /* 253 */
    {618, UINT32_C(0x1eaee4fe)}, /* 254 */
    {264, UINT32_C(0x9da101ff)}, /* 255 */
};

struct delivery {
    unsigned id, expected_owner, calls;
    struct ker_flow_key key;
    uint8_t frame[42];
};
static void receive(void *arg, const struct ker_flow_key *key, struct rte_mbuf *m)
{
    struct delivery *d = arg;
    CHECK(d->id == d->expected_owner);
    CHECK(key->domain == d->key.domain && key->family == 4 && key->protocol == 17);
    CHECK(key->local_port == 443 && key->remote_port == d->key.remote_port);
    CHECK(memcmp(key->local, d->key.local, 16) == 0);
    CHECK(memcmp(key->remote, d->key.remote, 16) == 0);
    CHECK(rte_pktmbuf_pkt_len(m) == sizeof(d->frame));
    CHECK(memcmp(rte_pktmbuf_mtod(m, void *), d->frame, sizeof(d->frame)) == 0);
    ++d->calls;
    rte_pktmbuf_free(m);
}
static void frame_for(struct delivery *d, bool egress)
{
    uint8_t *p = d->frame;
    memset(p, 0, sizeof(d->frame));
    p[12] = 8; p[14] = 0x45; p[17] = 28; p[22] = 64; p[23] = 17;
    memcpy(p + 26, (egress ? d->key.local : d->key.remote) + 12, 4);
    memcpy(p + 30, (egress ? d->key.remote : d->key.local) + 12, 4);
    unsigned src = egress ? 443 : d->key.remote_port;
    unsigned dst = egress ? d->key.remote_port : 443;
    p[34] = src >> 8; p[35] = src; p[36] = dst >> 8; p[37] = dst;
    p[39] = 8;
}
static void exercise(struct ker_packet_pool *pool, unsigned count, unsigned layout)
{
    uint16_t map[KER_FLOW_BUCKETS], expected[KER_FLOW_BUCKETS];
    for (unsigned b = 0; b < KER_FLOW_BUCKETS; ++b) {
        /* Rotated distribution, all to highest ID, and just the last bucket
         * to highest ID (other workers may legitimately own no buckets). */
        map[b] = layout == 0 ? (b + 1) % count :
            layout == 1 ? count - 1 : (b == 255 ? count - 1 : 0);
        expected[b] = map[b];
    }
    struct ker_flow_fabric fabric = {0};
    struct ker_flow_config cfg = {.worker_count=count, .bucket_owner=map,
        .seed=SEED, .inbox_capacity=1, .name="bucket_bounds", .socket_id=SOCKET_ID_ANY};
    CHECK(ker_flow_fabric_init(&fabric, &cfg) == 0);
    /* Input storage is borrowed only during initialization. Poison it before
     * attachment so both fabric and context snapshot semantics are exercised. */
    memset(map, 0xff, sizeof(map));
    struct ker_worker workers[KER_FLOW_MAX_WORKERS] = {0};
    struct ker_flow_context contexts[KER_FLOW_MAX_WORKERS] = {0};
    struct delivery deliveries[KER_FLOW_MAX_WORKERS] = {0};
    struct ker_worker_config wc = {.timer_budget=1, .handoff_budget=1};
    struct ker_worker_ops ops = {0};
    for (unsigned w = 0; w < count; ++w) {
        deliveries[w].id = w;
        CHECK(ker_worker_init(&workers[w], pool, &wc, &ops) == 0);
        CHECK(ker_flow_attach(&contexts[w], &fabric, &workers[w], w, receive, &deliveries[w]) == 0);
    }
    for (unsigned b = 0; b < 256; ++b) {
        struct ker_flow_key key = {.domain=7, .family=4, .protocol=17,
            .local_port=443, .remote_port=vectors[b].port,
            .local={[12]=10, [15]=1}, .remote={[12]=192, [14]=2, [15]=1}};
        uint32_t hash = 0;
        CHECK(ker_flow_hash(&key, SEED, &hash) == 0);
        CHECK(hash == vectors[b].hash && (hash & 255) == b);
        for (unsigned w = 0; w < count; ++w) {
            unsigned owner = UINT_MAX;
            CHECK(ker_flow_owner(&contexts[w], &key, &owner) == 0);
            CHECK(owner == expected[b]);
        }
        unsigned owner = expected[b];
        struct delivery *d = &deliveries[owner];
        d->expected_owner = owner; d->key = key;
        /* Exercise local and remote paths even for all-to-one maps. */
        for (unsigned path = 0; path < (count == 1 ? 1U : 2U); ++path) {
            unsigned source = path == 0 ? owner : (owner + 1) % count;
            for (unsigned direction = 0; direction < 2; ++direction) {
                frame_for(d, direction != 0);
                unsigned before = d->calls;
                struct rte_mbuf *m = ker_packet_alloc(pool);
                CHECK(m != NULL);
                void *bytes = rte_pktmbuf_append(m, sizeof(d->frame));
                CHECK(bytes != NULL); memcpy(bytes, d->frame, sizeof(d->frame));
                CHECK(ker_flow_submit(&contexts[source], 7,
                    direction ? KER_FLOW_EGRESS : KER_FLOW_INGRESS, &m) == 0 && m == NULL);
                CHECK(d->calls == before + (source == owner));
                struct ker_worker_result result;
                CHECK(ker_worker_poll(&workers[owner], 0, &result) == 0);
                CHECK(result.handoff == (source != owner));
                CHECK(d->calls == before + 1);
                CHECK(ker_flow_poll(&contexts[owner], 1) == 0);
            }
        }
    }
    for (unsigned w = 0; w < count; ++w) {
        CHECK(ker_flow_detach(&contexts[w]) == 0);
        CHECK(ker_worker_cleanup(&workers[w]) == 0);
    }
    CHECK(ker_flow_fabric_cleanup(&fabric) == 0);
}
static void invalid_configs(void)
{
    uint16_t map[KER_FLOW_BUCKETS] = {0};
    struct ker_flow_fabric fabric = {0};
    struct ker_flow_config cfg = {.worker_count=0, .bucket_owner=map,
        .seed=SEED, .inbox_capacity=1, .name="bucket_invalid", .socket_id=SOCKET_ID_ANY};
    CHECK(ker_flow_fabric_init(&fabric, &cfg) == -EINVAL);
    cfg.worker_count = KER_FLOW_MAX_WORKERS + 1;
    CHECK(ker_flow_fabric_init(&fabric, &cfg) == -EINVAL);
    for (unsigned count = 1; count <= KER_FLOW_MAX_WORKERS; ++count) {
        cfg.worker_count = count;
        for (unsigned b = 0; b < KER_FLOW_BUCKETS; ++b) {
            map[b] = count;
            CHECK(ker_flow_fabric_init(&fabric, &cfg) == -EINVAL);
            CHECK(!fabric.initialized && fabric.inbox == NULL);
            map[b] = UINT16_MAX;
            CHECK(ker_flow_fabric_init(&fabric, &cfg) == -EINVAL);
            map[b] = 0;
        }
    }
    cfg.bucket_owner = NULL;
    CHECK(ker_flow_fabric_init(&fabric, &cfg) == -EINVAL);
    CHECK(ker_flow_fabric_cleanup(&fabric) == 0);
}
int main(void)
{
    ker_test_eal_init();
    CHECK(ker_memory_init(SOCKET_ID_ANY, 7) == 0);
    struct ker_packet_pool pool = {0};
    CHECK(ker_packet_pool_init(&pool, "bucket_pool", 127, 0, 2048, SOCKET_ID_ANY) == 0);
    invalid_configs();
    for (unsigned count = 1; count <= KER_FLOW_MAX_WORKERS; ++count)
        for (unsigned layout = 0; layout < 3; ++layout) exercise(&pool, count, layout);
    CHECK(ker_packet_pool_cleanup(&pool) == 0);
    CHECK(ker_memory_shutdown() == 0);
    CHECK(rte_eal_cleanup() == 0);
    puts("flow buckets: all 256 buckets, worker counts 1..64, three layouts and invalid configurations passed");
    return 0;
}
