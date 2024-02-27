#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <fstream>

#include "utils.h"


int main(int argc, const char* argv[])
{
    std::cout << std::hex;

    auto q = uint32_t(0);
    auto I = std::array<uint8_t, 16>();

    if (argc != 4)
    {
        std::cout << "Incorrect input format" << std::endl;
        return -1;
    }

    auto I_str = std::string_view(argv[1]);
    auto q_str = std::string_view(argv[2]);
    if (utils::hex_to_bytes(I_str, I) != 16 || utils::hex_to_bytes(q_str, q) != 4)
    {
        std::cerr << "Error parsing I or q" << '\n';
        return -1;
    }
    


    std::ofstream output_file(argv[3]);
    if (!output_file.is_open())
    {
        std::cerr << "Could not open file." << '\n';
        return -1;
    }

    std::srand(std::time(nullptr));

    auto x = hash_array_p();
    for (size_t i = 0;i < p;i++)
    {
        std::transform(x[i].begin(), x[i].end(), x[i].begin(), [&]([[maybe_unused]] uint8_t v)
        {
            return static_cast<uint8_t>(std::rand());
        });
    }    
    output_file << std::hex;

    utils::print_bytes(output_file, I);
    utils::print_bytes(output_file, q);
    std::for_each(x.cbegin(), x.cend(), 
                [&output_file](const byte_string_n &arr) {
                utils::print_bytes(output_file, arr);
                });
    
    auto from = std::array<uint8_t, p>();
    from.fill(0);
    auto to = std::array<uint8_t, p>();
    to.fill(1 << w);
    utils::advance_hashes(x, from, to, I, q);

    auto output_hash = utils::public_hash(x, I, q);

    utils::print_hex(std::cout, typecode);
    utils::print_hex(std::cout, I);
    utils::print_hex(std::cout, q);
    utils::print_hex(std::cout, output_hash);
    std::cout << '\n';
}