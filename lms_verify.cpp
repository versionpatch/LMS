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
        
    if (argc != 4)
    {
        std::cerr << "Incorrect input format" << '\n';
        return -1;
    }


    auto I = std::array<uint8_t, 16>();
    auto public_hash = byte_string_n();
    {
        std::string_view pub_key_str = std::string_view(argv[1]);
        auto read_lms_type = uint32_t();
        auto read_ots_type = uint32_t();
        if (pub_key_str.size() != 2*(2*sizeof(uint32_t) + 16 + n))
        {
            std::cerr << "Incorrect public key size" << '\n';
            return -1;
        }
        auto read_bytes = utils::hex_to_bytes(pub_key_str, read_lms_type, read_ots_type, I, public_hash);
        if (read_bytes != pub_key_str.size()/2)
        {
            std::cerr << "Incorrect public key format" << '\n';
            return -1; 
        }
        if (read_lms_type != lms_typecode || read_ots_type != typecode)
        {
            std::cerr << "REJECT" << '\n';
            return -1;
        }
    }

    auto q = uint32_t(0);
    auto c = byte_string_n();
    auto ots_signature = hash_array_p();
    auto path = std::array<byte_string_n, h>();
    {
        auto read_lms_type = uint32_t();
        auto read_ots_type = uint32_t();
        auto signature_file = std::ifstream(argv[3]);
        if (!signature_file.is_open())
        {
            std::cerr << "Could not open signature file." << '\n';
            return -1;
        }
        auto read_bytes = size_t(0);
        read_bytes += utils::stream_to_bytes(signature_file, q, read_ots_type, c);
        for (size_t i = 0;i < p;i++)
            read_bytes += utils::stream_to_bytes(signature_file, ots_signature[i]);
        read_bytes += utils::stream_to_bytes(signature_file, read_lms_type);
        for (size_t i = 0;i < path.size();i++)
            read_bytes += utils::stream_to_bytes(signature_file, path[i]);
        if (read_bytes != 3*sizeof(uint32_t) + path.size()*n + p*n + n
            || read_lms_type != lms_typecode || read_ots_type != typecode)
        {
            std::cerr << "Incorrect signature format." << '\n';
            return -1;
        }
    }
    auto message_file = std::ifstream(argv[2]);
    if (!message_file.is_open())
    {
        std::cerr << "Could not open message file" << '\n';
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
    utils::advance_hashes(ots_signature, from, to, I, q);
    auto output_hash = utils::public_hash(ots_signature, I, q);

    auto r = q + (1 << h) - 1;
    output_hash = utils::leaf_hash(output_hash, r, I);
    
    for (size_t i = 0;i < path.size();i++)
    {
        if (r % 2 == 0)
        {
            r = (r / 2) - 1;
            output_hash = utils::node_hash(path[i], output_hash, r, I);
        }
        else
        {
            r = (r / 2);
            output_hash = utils::node_hash(output_hash, path[i], r, I);
        }
    }

    auto correct = std::equal(output_hash.cbegin(), output_hash.cend(), public_hash.cbegin());
    if (correct)
        std::cout << "ACCEPT" << std::endl;
    else
        std::cout << "REJECT" << std::endl;
    return 0;


}