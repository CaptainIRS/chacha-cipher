#ifdef LOGS_ENABLED
    #define log(x) std::cout << "\x1B[34mLOG: \x1B[0m" << x << std::endl;
#else
    #define log(x) do {} while (0)
#endif

typedef std::array<std::array<uint32_t, 4>, 4> block_t;

#define little(x) __builtin_bswap32(x)

void print_state(std::string title, block_t &state) {
    #ifdef LOGS_ENABLED
    log(title);
    for (int i = 0; i < 4; i++) {
        std::cout << "\t";
        for (int j = 0; j < 4; j++) {
            printf("%08x ", state[i][j]);
        }
        std::cout << std::endl;
    }
    #endif
}

void hexdump_string(std::string title, std::string &str) {
    #ifdef LOGS_ENABLED
    log(title);
    for (int i = 0; i < str.length() / 16 + 1; i++) {
        printf("%03d  ", i * 16);
        for (int j = 0; j < 16; j++) {
            if (i * 16 + j < str.length()) {
                printf("%02x ", (unsigned char) str[i * 16 + j]);
            } else {
                printf("   ");
            }
        }
        printf(" ");
        for (int j = 0; j < 16; j++) {
            if (i * 16 + j < str.length()) {
                printf("%c", (unsigned char) str[i * 16 + j] >= 32 && (unsigned char) str[i * 16 + j] <= 126 ? str[i * 16 + j] : '.');
            } else {
                printf(" ");
            }
        }
        printf("\n");
    }
    #endif
}

template<int N>
std::array<uint32_t, N> get_stream_from_string(std::string str) {
    std::array<uint32_t, N> result;
    
    str.erase(std::remove(str.begin(), str.end(), ':'), str.end());
    for (size_t i = 0; i < str.size(); i += 8) {
        std::string word_string = str.substr(i, 8);
        uint32_t word = std::stoul(word_string, nullptr, 16);
        result[i / 8] = little(word);
    }

    return result;
}
