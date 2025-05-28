#include "rnd_man.h"

#include <cstring>

namespace rnd {

RandManager::RandManager(int buff_size) : buff_size_(buff_size), 
          mdctx_(EVP_MD_CTX_new(), EVP_MD_CTX_free) {
  if(!mdctx_)
    throw std::runtime_error("Failed to create EVP_MD_CTX");
 }

void RandManager::Begin() {
  if (EVP_DigestInit_ex(mdctx_.get(), EVP_sha512(), nullptr) != 1)
    throw std::runtime_error("EVP_DigestInit_ex failed");
}

std::vector<uint8_t> RandManager::End() {
  unsigned int md_len = 0;
  md_.resize(EVP_MD_size(EVP_sha512()));
  if (EVP_DigestFinal_ex(mdctx_.get(), md_.data(), &md_len) != 1)
    throw std::runtime_error("EVP_DigestFinal_ex failed");
  
  std::vector<uint8_t> result(buff_size_);
  std::memcpy(result.data(), md_.data(), buff_size_);
  return result;
}

void RandManager::HashBuff(const uint8_t *buff, int size) {
  if (EVP_DigestUpdate(mdctx_.get(), buff, size) != 1)
    throw std::runtime_error("EVP_DigestUpdate failed");
}

}  // namespace rnd
