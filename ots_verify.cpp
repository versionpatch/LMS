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
    
    auto pkey_str = std::string_view(argv[1]);
    auto read_typecode = uint32_t();
    auto I = std::array<uint8_t, 16>();
    auto q = uint32_t(0);
    auto pk_hash = byte_string_n();
    auto pkey_str_size = utils::hex_to_bytes(pkey_str, read_typecode, I, q, pk_hash);
    if (pkey_str_size != (4 + 16 + 4 + n))
    {
        std::cerr << "Incorrect public key format" << std::endl;
        return -1;
    }

    auto signature_file = std::ifstream(argv[3], std::ios_base::binary);
    if (!signature_file.is_open())
    {
        std::cerr << "Could not open signature file" << std::endl;
        return -1;
    }

    auto signature_size = size_t(0);
    auto c = byte_string_n();
    auto sig = hash_array_p();
    signature_size += utils::stream_to_bytes(signature_file, read_typecode, c);
    if (read_typecode != typecode)
    {
        std::cout << "REJECT" << '\n';
        return -1;
    }
    std::for_each(sig.begin(), sig.end(), 
                  [&](byte_string_n &arr) {
                    signature_size += utils::stream_to_bytes(signature_file, arr);
                   });

    if (signature_size != sizeof(typecode) + n + n*p)
    {
        std::cerr << "Incorrect signature size" << std::endl;
        return -1;
    }

    auto message_file = std::ifstream(argv[2], std::ios_base::binary);
    if (!message_file.is_open())
    {
        std::cerr << "Error opening message file" << std::endl;
        return -1;
    }

    auto q_hash = utils::message_hash(message_file, c, I, q);

    uint32_t chksm = checksum(q_hash);
    auto q_chksm = std::vector<uint8_t>(q_hash.cbegin(), q_hash.cend());
    q_chksm.insert(q_chksm.end(), reinterpret_cast<uint8_t*>(&chksm), 
                                  reinterpret_cast<uint8_t*>(&chksm) + sizeof(chksm));

    auto from = std::array<uint8_t, p>();
    std::iota(from.begin(), from.end(), 0);
    std::transform(from.begin(), from.end(), from.begin(), [&](uint8_t i) {return coef(q_chksm, i);});
    auto to = std::array<uint8_t, p>();
    to.fill(1 << w);

    utils::advance_hashes(sig, from, to, I, q);
    
    auto output_hash = utils::public_hash(sig, I, q);
    
    auto is_correct = std::equal(output_hash.cbegin(), output_hash.cend(), pk_hash.cbegin());

    if (is_correct)
        std::cout << "ACCEPT" << "\n";
    else
        std::cout << "REJECT" << "\n";
    

    return 0;
}