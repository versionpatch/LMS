#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <fstream>
#include <charconv>
#include <numeric>


#include "utils.h"

int main(int argc, const char* argv[])
{
    std::cout << std::hex;
    std::srand(std::time(nullptr));

    if (argc != 5)
    {
        std::cerr << "Incorrect input format" << '\n';
        return -1;
    }

    auto private_key_file = std::ifstream(argv[1]);
    if (!private_key_file.is_open())
    {
        std::cerr << "Could not open private key file." << '\n';
        return -1;
    }

    auto I = std::array<uint8_t, 16>();
    auto private_key = pkey_array_h();
    auto hash_tree = hash_tree_h();
    {
        auto private_key_size = size_t(0);
        private_key_size += utils::stream_to_bytes(private_key_file, I);
        for (uint32_t q = 0;q < 1<<h;q++)
        {
            for (uint32_t i = 0;i < p;i++)
            {
                private_key_size += utils::stream_to_bytes(private_key_file, private_key[q][i]);
            }
        }
        for (uint32_t r = 0;r < hash_tree.size();r++)
        {
            private_key_size += utils::stream_to_bytes(private_key_file, hash_tree[r]);
        }
        if (private_key_size != 16 + (1<<h)*p*n + hash_tree.size()*n)
        {
            std::cerr << "Incorrect private key format." << '\n';
            return -1;
        }
    }

    auto idx = uint32_t(0);
    {
        auto index_str = std::string_view(argv[2]);
        auto [ptr, err] = std::from_chars(index_str.begin(), index_str.end(), idx);
        if (err != std::errc() || idx >= private_key.size())
        {
            std::cerr << "Incorrect index." << '\n';
            return -1;
        }
    }

    auto message_file = std::ifstream(argv[3]);
    if (!message_file.is_open())
    {
        std::cerr << "Could not open message file" << '\n';
        return -1;
    }

    auto c = byte_string_n();
    std::transform(c.begin(), c.end(), c.begin(), [&]([[maybe_unused]] uint8_t v)
    {
        return static_cast<uint8_t>(std::rand());
    });

    auto q_hash = utils::message_hash(message_file, c, I, idx);
    uint32_t chksm = checksum(q_hash);
    auto q_chksm = std::vector<uint8_t>(q_hash.cbegin(), q_hash.cend());
    q_chksm.insert(q_chksm.end(), reinterpret_cast<uint8_t*>(&chksm), 
                                  reinterpret_cast<uint8_t*>(&chksm) + sizeof(chksm));
    
    auto from = std::array<uint8_t, p>();
    from.fill(0);
    auto to = std::array<uint8_t, p>();
    std::iota(to.begin(), to.end(), 0);
    std::transform(to.begin(), to.end(), to.begin(), [&](uint8_t i) {return coef(q_chksm, i);});
    utils::advance_hashes(private_key[idx], from, to, I, idx);

    auto signature_file = std::ofstream(argv[4]);
    if (!signature_file.is_open())
    {
        std::cerr << "Could not open signature file" << '\n';
        return -1;
    }

    utils::print_bytes(signature_file, idx);
    utils::print_bytes(signature_file, typecode);
    utils::print_bytes(signature_file, c);
    for (uint32_t i = 0;i < p;i++)
        utils::print_bytes(signature_file, private_key[idx][i]);
    utils::print_bytes(signature_file, lms_typecode);
    uint32_t cur_val = idx + (1 << h) - 1;

    while (cur_val != 0)
    {
        if (cur_val % 2 == 0)
        {
            utils::print_bytes(signature_file, hash_tree[cur_val - 1]);
            cur_val = (cur_val / 2) - 1;
        }
        else
        {
            utils::print_bytes(signature_file, hash_tree[cur_val + 1]);
            cur_val = (cur_val / 2);
        }
    }

    return 0;
}