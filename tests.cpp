#define CATCH_CONFIG_MAIN

#include <catch2/catch.hpp>

#include "chacha.hpp"

#define little(x) __builtin_bswap32(x)

TEST_CASE("ChaCha Quarter Round", "[chacha]") {
    SECTION("Quarter Round Operation") {
        uint32_t a = 0x11111111;
        uint32_t b = 0x01020304;
        uint32_t c = 0x9b8d6f43;
        uint32_t d = 0x01234567;
        quarter_round_operation(a, b, c, d);
        REQUIRE(a == 0xea2a92f4);
        REQUIRE(b == 0xcb1cf8ce);
        REQUIRE(c == 0x4581472e);
        REQUIRE(d == 0x5881c4bb);
    }

    SECTION("Quarter Round on ChaCha State") {
        block_t state = {{
            {0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a},
            {0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c},
            {0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963},
            {0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320}
        }};
        chacha_quarter_round(state, 2, 7, 8, 13);

        block_t expected_state = {{
            {0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a},
            {0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2},
            {0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963},
            {0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320}
        }};
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 4; j++) {
                REQUIRE(state[i][j] == expected_state[i][j]);
            }
        }
    }
}


TEST_CASE("ChaCha Block Function", "[chacha]") {
    SECTION("Initial State") {
        std::array<uint32_t, 8> key = {{
            little(0x00010203), little(0x04050607), little(0x08090a0b), little(0x0c0d0e0f),
            little(0x10111213), little(0x14151617), little(0x18191a1b), little(0x1c1d1e1f)
        }};
        std::array<uint32_t, 3> nonce = {{
            little(0x00000009), little(0x0000004a), little(0x00000000)
        }};
        uint32_t count = 1;
        
        block_t initial_state = get_initial_state(key, nonce, count);
        
        block_t expected_state = {{
            {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574},
            {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c},
            {0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c},
            {0x00000001, 0x09000000, 0x4a000000, 0x00000000}
        }};
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 4; j++) {
                REQUIRE(initial_state[i][j] == expected_state[i][j]);
            }
        }
    }

    SECTION("After 20 rounds") {
        block_t state = {{
            {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574},
            {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c},
            {0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c},
            {0x00000001, 0x09000000, 0x4a000000, 0x00000000}
        }};

        chacha_inner_block(state);

        block_t expected_state = {{
            {0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f},
            {0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7},
            {0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd},
            {0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2}
        }};
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 4; j++) {
                REQUIRE(state[i][j] == expected_state[i][j]);
            }
        }
    }

    SECTION("Add working state to initial state") {
        block_t initial_state = {{
            {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574},
            {0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c},
            {0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c},
            {0x00000001, 0x09000000, 0x4a000000, 0x00000000}
        }};

        block_t working_state = {{
            {0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f},
            {0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7},
            {0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd},
            {0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2}
        }};

        add_blocks(initial_state, working_state);

        block_t expected_state = {{
            {0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3},
            {0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3},
            {0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9},
            {0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2}
        }};
        for (size_t i = 0; i < 4; i++) {
            for (size_t j = 0; j < 4; j++) {
                REQUIRE(initial_state[i][j] == expected_state[i][j]);
            }
        }
    }

    SECTION("Serialize state") {
        block_t state = {{
            {0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3},
            {0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3},
            {0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9},
            {0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2}
        }};

        std::string serialized = serialize_state(state);

        std::string expected_serialized = new char[64] {
            '\x10', '\xf1', '\xe7', '\xe4', '\xd1', '\x3b', '\x59', '\x15', '\x50', '\x0f', '\xdd', '\x1f', '\xa3', '\x20', '\x71', '\xc4',
            '\xc7', '\xd1', '\xf4', '\xc7', '\x33', '\xc0', '\x68', '\x03', '\x04', '\x22', '\xaa', '\x9a', '\xc3', '\xd4', '\x6c', '\x4e',
            '\xd2', '\x82', '\x64', '\x46', '\x07', '\x9f', '\xaa', '\x09', '\x14', '\xc2', '\xd7', '\x05', '\xd9', '\x8b', '\x02', '\xa2',
            '\xb5', '\x12', '\x9c', '\xd1', '\xde', '\x16', '\x4e', '\xb9', '\xcb', '\xd0', '\x83', '\xe8', '\xa2', '\x50', '\x3c', '\x4e'
        };
        REQUIRE(serialized == expected_serialized);   
    }
}

TEST_CASE("ChaCha Utils", "[chacha]") {
    SECTION("Get Key from String") {
        std::string key_string = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
        std::array<uint32_t, 8> key = get_stream_from_string<8>(key_string);

        std::array<uint32_t, 8> expected_key = {{
            little(0x00010203), little(0x04050607), little(0x08090a0b), little(0x0c0d0e0f),
            little(0x10111213), little(0x14151617), little(0x18191a1b), little(0x1c1d1e1f)
        }};

        for (size_t i = 0; i < 8; i++) {
            REQUIRE(key[i] == expected_key[i]);
        }
    }

    SECTION("Get Nonce from String") {
        std::string nonce_string = "00:00:00:09:00:00:00:4a:00:00:00:00";
        std::array<uint32_t, 3> nonce = get_stream_from_string<3>(nonce_string);

        std::array<uint32_t, 3> expected_nonce = {{
            little(0x00000009), little(0x0000004a), little(0x00000000)
        }};

        for (size_t i = 0; i < 3; i++) {
            REQUIRE(nonce[i] == expected_nonce[i]);
        }
    }

    SECTION("Xor Strings") {
        std::string a = "\x01\x02\x03\x04";
        std::string b = "\x05\x06\x07\x08";

        std::string xor_string = xor_strings(a, b);

        std::string expected_xor_string = "\x04\x04\x04\x0c";
        REQUIRE(xor_string == expected_xor_string);
    }
}

TEST_CASE("ChaCha Encrypt and Decrypt", "[chacha]") {
    SECTION("Encrypt plaintext") {
        std::string plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        std::string key_string = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
        std::string nonce_string = "00:00:00:00:00:00:00:4a:00:00:00:00";

        std::string ciphertext = chacha_encrypt(plaintext, key_string, nonce_string, 1);
        std::string expected_ciphertext = new char[] {
            '\x6e', '\x2e', '\x35', '\x9a', '\x25', '\x68', '\xf9', '\x80', '\x41', '\xba', '\x07', '\x28', '\xdd', '\x0d', '\x69', '\x81',
            '\xe9', '\x7e', '\x7a', '\xec', '\x1d', '\x43', '\x60', '\xc2', '\x0a', '\x27', '\xaf', '\xcc', '\xfd', '\x9f', '\xae', '\x0b',
            '\xf9', '\x1b', '\x65', '\xc5', '\x52', '\x47', '\x33', '\xab', '\x8f', '\x59', '\x3d', '\xab', '\xcd', '\x62', '\xb3', '\x57',
            '\x16', '\x39', '\xd6', '\x24', '\xe6', '\x51', '\x52', '\xab', '\x8f', '\x53', '\x0c', '\x35', '\x9f', '\x08', '\x61', '\xd8',
            '\x07', '\xca', '\x0d', '\xbf', '\x50', '\x0d', '\x6a', '\x61', '\x56', '\xa3', '\x8e', '\x08', '\x8a', '\x22', '\xb6', '\x5e',
            '\x52', '\xbc', '\x51', '\x4d', '\x16', '\xcc', '\xf8', '\x06', '\x81', '\x8c', '\xe9', '\x1a', '\xb7', '\x79', '\x37', '\x36',
            '\x5a', '\xf9', '\x0b', '\xbf', '\x74', '\xa3', '\x5b', '\xe6', '\xb4', '\x0b', '\x8e', '\xed', '\xf2', '\x78', '\x5e', '\x42',
            '\x87', '\x4d'
        };

        REQUIRE(ciphertext == expected_ciphertext);
    }

    SECTION("Decrypt ciphertext") {
        std::string ciphertext = new char[] {
            '\x6e', '\x2e', '\x35', '\x9a', '\x25', '\x68', '\xf9', '\x80', '\x41', '\xba', '\x07', '\x28', '\xdd', '\x0d', '\x69', '\x81',
            '\xe9', '\x7e', '\x7a', '\xec', '\x1d', '\x43', '\x60', '\xc2', '\x0a', '\x27', '\xaf', '\xcc', '\xfd', '\x9f', '\xae', '\x0b',
            '\xf9', '\x1b', '\x65', '\xc5', '\x52', '\x47', '\x33', '\xab', '\x8f', '\x59', '\x3d', '\xab', '\xcd', '\x62', '\xb3', '\x57',
            '\x16', '\x39', '\xd6', '\x24', '\xe6', '\x51', '\x52', '\xab', '\x8f', '\x53', '\x0c', '\x35', '\x9f', '\x08', '\x61', '\xd8',
            '\x07', '\xca', '\x0d', '\xbf', '\x50', '\x0d', '\x6a', '\x61', '\x56', '\xa3', '\x8e', '\x08', '\x8a', '\x22', '\xb6', '\x5e',
            '\x52', '\xbc', '\x51', '\x4d', '\x16', '\xcc', '\xf8', '\x06', '\x81', '\x8c', '\xe9', '\x1a', '\xb7', '\x79', '\x37', '\x36',
            '\x5a', '\xf9', '\x0b', '\xbf', '\x74', '\xa3', '\x5b', '\xe6', '\xb4', '\x0b', '\x8e', '\xed', '\xf2', '\x78', '\x5e', '\x42',
            '\x87', '\x4d'
        };
        std::string key_string = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
        std::string nonce_string = "00:00:00:00:00:00:00:4a:00:00:00:00";

        std::string plaintext = chacha_encrypt(ciphertext, key_string, nonce_string, 1);

        std::string expected_plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        REQUIRE(plaintext == expected_plaintext);
    }
}