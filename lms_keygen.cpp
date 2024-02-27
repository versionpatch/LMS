#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <fstream>

#include "utils.h"

int main(int argc, const char* argv[])
{
    std::cout << std::hex;
    std::srand(std::time(nullptr));

    if (argc != 2)
    {
        std::cerr << "Incorrect input format" << '\n';
        return -1;
    }
    auto private_key_file = std::ofstream(argv[1]);
    if (!private_key_file.is_open())
    {
        std::cerr << "Could not open output file." << '\n';
        return -1;
    }

    auto I = std::array<uint8_t, 16>();
    std::transform(I.begin(), I.end(), I.begin(), [&]([[maybe_unused]] uint8_t v)
    {
        return static_cast<uint8_t>(std::rand());
    });

    utils::print_bytes(private_key_file, I);

    auto private_key = pkey_array_h();
    for (uint32_t q = 0;q < 1 << h;q++)
    {
        for (uint32_t i = 0;i < p;i++)
        {
            std::transform(private_key[q][i].begin(), private_key[q][i].end(), 
                           private_key[q][i].begin(), [&]([[maybe_unused]] uint8_t v)
            {
                return static_cast<uint8_t>(std::rand());
            });
            utils::print_bytes(private_key_file, private_key[q][i]);
        }
    }

    auto from = std::array<uint8_t, p>();
    from.fill(0);
    auto to = std::array<uint8_t, p>();
    to.fill(1 << w);
    for (uint32_t q = 0;q < 1 << h;q++)
    {
        utils::advance_hashes(private_key[q], from, to, I, q);
    }

    auto hash_tree = hash_tree_h();
    for (int r = hash_tree.size() - 1;r >= 0;r--)
    {
        if (r >= (1 << h) - 1)
        {
            uint32_t leaf_idx = r - ((1 << h) - 1);
            auto pub_key = utils::public_hash(private_key[leaf_idx], I, leaf_idx);
            hash_tree[r] = utils::leaf_hash(pub_key, static_cast<uint32_t>(r), I);
        }
        else
        {
            hash_tree[r] = utils::node_hash(hash_tree[2*r + 1], hash_tree[2*r + 2], static_cast<uint32_t>(r), I);
        }
        
    }
    for (uint32_t r = 0; r < hash_tree.size(); r++)
        utils::print_bytes(private_key_file, hash_tree[r]);

    utils::print_hex(std::cout, lms_typecode);
    utils::print_hex(std::cout, typecode);
    utils::print_hex(std::cout, I);
    utils::print_hex(std::cout, hash_tree[0]);
    std::cout << '\n';


    return 0;
}