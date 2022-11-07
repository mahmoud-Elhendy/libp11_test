#include "secure_element.h"

SecureElement::SecureElement(){
    unsigned int nslots;
    ctx = PKCS11_CTX_new();
    //TODO throw error
	
    /* load pkcs #11 module */	
    PKCS11_CTX_load(ctx, PKCS11_MODULE);
    PKCS11_enumerate_slots(ctx, &slots, &nslots);
}

EVP_PKEY* SecureElement::get_key(){
    
    PKCS11_KEY* keys;
	unsigned int nkeys = 0;

	PKCS11_SLOT *slot = PKCS11_find_token(ctx, slots, nslots);
    
    /* get public keys */
	int rc = PKCS11_enumerate_public_keys(slot->token, &keys, &nkeys);
    if (rc < 0 || 0 == nkeys)
        return nullptr;

    for (unsigned int i = 0; i < nkeys; i++)
		if (0 == strcmp(keys[i].label,KEY_LABEL))
            return &keys[i];
    
    return nullptr;
}

bool SecureElement::import(){   
    if (- 1 == system(SE_IMPORT_CMD)) {
        return false;
    }
    return true;
}