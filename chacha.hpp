#include <iostream>

#include "utils.hpp"

void quarter_round_operation(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8) | (d >> 24);
    c += d; b ^= c; b = (b << 7) | (b >> 25);
}

void chacha_quarter_round(block_t &state, size_t x, size_t y, size_t z, size_t w) {
    quarter_round_operation(
        state[x / 4][x % 4],
        state[y / 4][y % 4],
        state[z / 4][z % 4],
        state[w / 4][w % 4]
    );
}

void chacha_inner_block(block_t &state) {
    for (size_t i = 0; i < 10; i++) {
        // Column round
        chacha_quarter_round(state, 0, 4, 8, 12);
        chacha_quarter_round(state, 1, 5, 9, 13);
        chacha_quarter_round(state, 2, 6, 10, 14);
        chacha_quarter_round(state, 3, 7, 11, 15);

        // Diagonal round
        chacha_quarter_round(state, 0, 5, 10, 15);
        chacha_quarter_round(state, 1, 6, 11, 12);
        chacha_quarter_round(state, 2, 7, 8, 13);
        chacha_quarter_round(state, 3, 4, 9, 14);
    }

    print_state("State after quarter rounds:", state);
}

block_t get_initial_state(std::array<uint32_t, 8> key, std::array<uint32_t, 3> nonce, uint32_t count) {
    block_t state = {{
        {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574},
        {key[0],     key[1],     key[2],     key[3]},
        {key[4],     key[5],     key[6],     key[7]},
        {count,      nonce[0],   nonce[1],   nonce[2]}
    }};

    print_state("Initial state:", state);
    return state;
}

void add_blocks(block_t &dest, block_t &src) {
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            dest[i][j] += src[i][j];
        }
    }

    print_state("State after adding blocks:", dest);
}

std::string serialize_state(block_t &state) {
    std::string result;
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            result += (char) (state[i][j] & 0xff);
            result += (char) ((state[i][j] >> 8) & 0xff);
            result += (char) ((state[i][j] >> 16) & 0xff);
            result += (char) ((state[i][j] >> 24) & 0xff);
        }
    }
    return result;
}

std::string chacha_block(std::array<uint32_t, 8> key, std::array<uint32_t, 3> nonce, uint32_t count) {
    block_t state = get_initial_state(key, nonce, count);
    block_t working_state = state;
    
    chacha_inner_block(working_state);

    add_blocks(state, working_state);

    std::string result = serialize_state(state);
    return result;
}

std::string xor_strings(std::string a, std::string b) {
    std::string result;
    for (size_t i = 0; i < a.size(); i++) {
        result += (char) (a[i] ^ b[i]);
    }
    return result;
}

std::string chacha_encrypt(std::string &plaintext, std::string key_string, std::string nonce_string, uint32_t count) {
    hexdump_string("Plaintext:", plaintext);
    
    std::string encrypted_message;
    size_t blocks_count = plaintext.size() / 64;
    std::array<uint32_t, 8> key = get_stream_from_string<8>(key_string);
    std::array<uint32_t, 3> nonce = get_stream_from_string<3>(nonce_string);
    
    for (size_t i = 0; i < blocks_count; i++) {
        log("Processing block " << i + 1);
        std::string key_stream = chacha_block(key, nonce, count + i);
        std::string block = plaintext.substr(i * 64, 64);
        encrypted_message += xor_strings(block, key_stream);
    }
    
    if (plaintext.size() % 64 != 0) {
        log("Processing block " << blocks_count + 1);
        std::string key_stream = chacha_block(key, nonce, count + blocks_count);
        std::string block = plaintext.substr(blocks_count * 64, plaintext.size() % 64);
        encrypted_message += xor_strings(block, key_stream);
    }

    hexdump_string("Encrypted message:", encrypted_message);

    return encrypted_message;
}