#pragma once 

#include <libp11.h>
#include <string>

const std::string PKCS11_MODULE = "/usr/lib/libckteec.so.0";
const std::string KEY_LABEL = "SE_00005002";
const std::string PIN = "12345678";
const std::string TOKEN_LABEL = "fio";
const std::string KEY_ID = "01";
const std::string SE_IMPORT_CMD = "pkcs11-tool --module "+ PKCS11_MODULE +
" --keypairgen --key-type EC:prime256v1--id "+KEY_ID+" --token-label "+TOKEN_LABEL +" --pin "+PIN +"--label "+KEY_LABEL;

class SecureElement{
public:
    SecureElement();
    bool import();
    EVP_PKEY* get_key();
    ~SecureElement();
private:
    PKCS11_CTX *ctx;
    PKCS11_SLOT *slots;
    unsigned int nslots;
}