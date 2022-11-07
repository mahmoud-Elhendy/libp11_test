#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <libp11.h>
#include <unistd.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <chrono>
#include <iostream>
using namespace std::chrono;

#define RANDOM_SOURCE "/dev/urandom"
#define RANDOM_SIZE 20
#define MAX_SIGSIZE 256

static void list_keys(const char *title,
	const PKCS11_KEY *keys, const unsigned int nkeys);

static PKCS11_KEY * get_root_pubkey(PKCS11_KEY *keys,const unsigned int nkeys);


const char* int_cert = R""""(-----BEGIN CERTIFICATE-----
MIIBmDCCAT4CFE7jcrchzCKG5eBFxvjf1WvlTzmgMAoGCCqGSM49BAMCMFgxCzAJ
BgNVBAYTAkVHMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQKDARmb3J0MQ0w
CwYDVQQLDARmb3J0MRYwFAYDVQQDDA1mb3J0IHJvYm90aWNzMB4XDTIyMTAyNTAw
NDQwM1oXDTI1MDcyMTAwNDQwM1owRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNv
bWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABLX7E+TqcueBB+rcgC3ZEqOYuKsRoXuD6UVa
34yR7Z5I9Z6ELHGrf9r4JDVvvLI8dABya57JUwX1uvippZJC6wAwCgYIKoZIzj0E
AwIDSAAwRQIgPh5//zPHODWms1XExOjuvEtftDguU6P/vpvGwZqvylwCIQDZ1p20
d8InpfTPITtbXVcKk7hzucVPVitdyI3WG4aDCg==
-----END CERTIFICATE-----
)"""";

int sig_verify(EVP_PKEY* signing_key, const char* intermediate_pem)
{
 
    BIO *c = BIO_new(BIO_s_mem());
    BIO_puts(c, intermediate_pem);
    X509 * x509 = PEM_read_bio_X509(c, NULL, NULL, NULL);
 
    int result = X509_verify(x509, signing_key);
 
    EVP_PKEY_free(signing_key);
    BIO_free(c);
    X509_free(x509);
 
    return result;
}

int main(int argc, char *argv[])
{
    std::chrono::time_point<std::chrono::_V2::system_clock, std::chrono::duration<long long int, std::ratio<1, 1000000000> > > start,stop;
    std::chrono::duration<long long int, std::ratio<1, 1000000> > duration;

	PKCS11_CTX *ctx=NULL;
	PKCS11_SLOT *slots=NULL, *slot;
	PKCS11_KEY *keys, *p_key;
	unsigned int nslots, nkeys;
    EVP_PKEY* root_pubkey;
	int rc = 0;

	if (argc < 2) {
		fprintf(stderr,
			"usage: %s /usr/lib/opensc-pkcs11.so [PIN]\n",
			argv[0]);
		return 1;
	}

	ctx = PKCS11_CTX_new();

	/* load pkcs #11 module */
	rc = PKCS11_CTX_load(ctx, argv[1]);

    start = high_resolution_clock::now();

	/* get information on all slots */
	rc = PKCS11_enumerate_slots(ctx, &slots, &nslots);


	/* get first slot with a token */
	slot = PKCS11_find_token(ctx, slots, nslots);

	/* get public keys */
	rc = PKCS11_enumerate_public_keys(slot->token, &keys, &nkeys);

    stop = high_resolution_clock::now();
    duration = duration_cast<microseconds>(stop - start);
 
    std::cout << "Time taken: "
         << duration.count() << " microseconds" << std::endl;

    
    p_key = get_root_pubkey(keys,nkeys);
    root_pubkey =   PKCS11_get_public_key(p_key);
	
    if(!sig_verify(root_pubkey,int_cert)){
        printf("%s","cert verification failed\n");
    }
    else{
        printf("%s","cert verification success\n");
    }

	if (slots)
		PKCS11_release_all_slots(ctx, slots, nslots);
	if (ctx) {
		PKCS11_CTX_unload(ctx);
		PKCS11_CTX_free(ctx);
	}

	if (rc)
		printf("Failed (error code %d).\n", rc);
	else
		printf("Success.\n");
	return rc;
}

static void list_keys(const char *title, const PKCS11_KEY *keys,
		const unsigned int nkeys) {
	unsigned int i;

	printf("\n%s:\n", title);
	for (i = 0; i < nkeys; i++)
		printf(" * %s key: %s\n",
			keys[i].isPrivate ? "Private" : "Public", keys[i].label);
}

static PKCS11_KEY * get_root_pubkey(PKCS11_KEY *keys,const unsigned int nkeys){
    unsigned int i;
    const char* label = "rootpubkey";
	for (i = 0; i < nkeys; i++)
		if (0 == strcmp(keys[i].label,label)){
            return &keys[i];
    }
    return nullptr;
}

