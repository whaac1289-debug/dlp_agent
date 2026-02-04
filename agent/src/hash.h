#pragma once
#include <string>
std::string sha256_hex(const void *data, size_t len);
std::string hmac_sha256_hex(const std::string &key, const std::string &data);
