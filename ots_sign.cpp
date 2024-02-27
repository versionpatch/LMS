#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <fstream>
#include <numeric>

#include "sha256.h"
#include "utils.h"


int main(int argc, const char* argv[])
{   
    std::srand(std::time(nullptr));
    std::cout << std::hex;

    if (argc != 4)
    {
        std::cerr << "Incorrect input format" << std::endl;
        return -1;
    }
    auto private_key_file = std::ifstream(argv[1]);
    auto message_file = std::ifstream(argv[2], std::ios_base::binary);
    auto signature_file = std::ofstream(argv[3], std::ios_base::binary);
    if (!private_key_file.is_open() || !message_file.is_open() || !signature_file.is_open())
    {
        std::cerr << "Error opening one of the three files." << std::endl;
        return -1;
    }

    auto I = std::array<uint8_t, 16>();
    auto q = uint32_t(0);
    auto x = hash_array_p();
    auto pkey_size = size_t(0);

    pkey_size += utils::stream_to_bytes(private_key_file, I, q);
    std::for_each(x.begin(), x.end(), [&](byte_string_n &arr) {
        pkey_size += utils::stream_to_bytes(private_key_file, arr);
    });
    if (pkey_size != (16 + sizeof(uint32_t) + n*p))
    {
        std::cerr << "Incorrect private key format" << std::endl;
        return -1;   
    }

    auto c = byte_string_n();
    std::transform(c.begin(), c.end(), c.begin(), [&]([[maybe_unused]] uint8_t v)
    {
        return static_cast<uint8_t>(std::rand());
    });

    auto q_hash = utils::message_hash(message_file, c, I, q);

    uint32_t chksm = checksum(q_hash);
    auto q_chksm = std::vector<uint8_t>(q_hash.cbegin(), q_hash.cend());
    q_chksm.insert(q_chksm.end(), reinterpret_cast<uint8_t*>(&chksm), 
                                  reinterpret_cast<uint8_t*>(&chksm) + sizeof(chksm));

    auto from = std::array<uint8_t, p>();
    from.fill(0);
    auto to = std::array<uint8_t, p>();
    std::iota(to.begin(), to.end(), 0);
    std::transform(to.begin(), to.end(), to.begin(), [&](uint8_t i) {return coef(q_chksm, i);});
    utils::advance_hashes(x, from, to, I, q);

    utils::print_bytes(signature_file, typecode);
    utils::print_bytes(signature_file, c);
    std::for_each(x.cbegin(), x.cend(), 
                  [&signature_file](const byte_string_n &arr) {
                    utils::print_bytes(signature_file, arr);
                 });
    return 0;
}