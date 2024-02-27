OTS is an implementation of LMSOTS_SHA256_N32_W4. 
LMS is an implementation of LMS_SHA256_M32_H5.

SHA256 is the hash function used.

ots_keygen takes q (a 4-byte hex-encoded string) and I (a 16-byte encoded string) and a file where the private key will be stored.  It will print the public key.
ots_sign takes a private key file, an input file, and a signature file  as command-line arguments.  It will compute the SHA256 hash of the input data file, generate the LMS signature for this hash, and write the result to the signature file.
ots_verify will take a hex-encoded public key, the name of a data file, and the name of a signature file; it will print ACCEPT if the signature is valid and REJECT if the signature is invalid.

lms_keygen generates a public-private key pair.  The private key is stored in the file specified by a command line argument.  The public key is printed as a hex-encoded byte string.
lms_sign will take a private key filename, an index, an input data filename, and an output signature filename on the command line, and write the LMS signature (using the OTS specified by the index) to the signature file. 
lms_verify will take a hex-encoded public key, the name of a data file, and the name of a signature file, and print ACCEPT or REJECT.
