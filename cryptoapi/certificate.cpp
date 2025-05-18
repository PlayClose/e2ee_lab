#include <stdexcept>
#include <iostream>
#include "certificate.h"

namespace playclose {
	namespace crypto {

void x509_certificate::set_cert_ca(std::unique_ptr<X509, deleter<X509_free>> ca_cert) {
	ca_cert_ = std::move(ca_cert);
}

void x509_certificate::set_cert_ca(const std::string& cert) {
	set_cert_ca(pem_to_x509(cert));
}

void x509_certificate::set_cert_csr(std::unique_ptr<X509_REQ, deleter<X509_REQ_free>> csr_cert) {
	csr_cert_ = std::move(csr_cert);
}

void x509_certificate::set_cert_csr(const std::string& cert) {
	set_cert_csr(pem_to_x509req(cert));
}

std::string x509_certificate::x509_to_pem() {
	if(!ca_cert_) {
		throw std::runtime_error("Invalid certificate pointer");
	}
	//Create memory BIO to hold PEM data
	std::unique_ptr<BIO, deleter<BIO_free>> bio(BIO_new(BIO_s_mem()));
	if(!bio) {
		throw std::runtime_error("Failed to create BIO");
	}
	//Write certificate in PEM format to BIO
	if(!PEM_write_bio_X509(bio.get(), ca_cert_.get())) {
		throw std::runtime_error("Failed to write certificate to BIO");
	}
	//Get the PEM data from BIO
	char* pem_data = nullptr;
	auto pem_size = BIO_get_mem_data(bio.get(), &pem_data);
	if(pem_size <= 0 || !pem_data) {
		throw std::runtime_error("Failed to get PEM data from BIO");
	}

	return std::string(pem_data, pem_size);
}

std::string x509_certificate::x509_to_pem(X509* cert) {
	if(!cert) {
		throw std::runtime_error("Invalid certificate pointer");
	}
	//Create memory BIO to hold PEM data
	std::unique_ptr<BIO, deleter<BIO_free>> bio(BIO_new(BIO_s_mem()));
	if(!bio) {
		throw std::runtime_error("Failed to create BIO");
	}
	//Write certificate in PEM format to BIO
	if(!PEM_write_bio_X509(bio.get(), cert)) {
		throw std::runtime_error("Failed to write certificate to BIO");
	}
	//Get the PEM data from BIO
	char* pem_data = nullptr;
	auto pem_size = BIO_get_mem_data(bio.get(), &pem_data);
	if(pem_size <= 0 || !pem_data) {
		throw std::runtime_error("Failed to get PEM data from BIO");
	}

	return std::string(pem_data, pem_size);
}

std::string x509_certificate::x509req_to_pem() {
	if(!csr_cert_) {
        throw std::runtime_error("Invalid certificate pointer");
    }
    //Create memory BIO to hold PEM data
    std::unique_ptr<BIO, deleter<BIO_free_all>> bio{BIO_new(BIO_s_mem())};
    if(!bio) {
        throw std::runtime_error("Failed to create BIO");
    }
    //Write certificate in PEM format to BIO
    if(!PEM_write_bio_X509_REQ(bio.get(), csr_cert_.get())) {
        throw std::runtime_error("Failed to write certificate to BIO");
    }
    //Get the PEM data from BIO
    char* pem_data = nullptr;
    long pem_size = BIO_get_mem_data(bio.get(), &pem_data);
    if(pem_size <= 0 || !pem_data) {
        throw std::runtime_error("Failed to get PEM data from BIO");
    }

    return std::string(pem_data, pem_size);
}

std::unique_ptr<X509_REQ, deleter<X509_REQ_free>> x509_certificate::pem_to_x509req(const std::string& pem_data) {
	std::unique_ptr<BIO, deleter<BIO_free>> bio{BIO_new_mem_buf(pem_data.data(), pem_data.size())};
    if(!bio) {
		std::runtime_error("Error creating BIO");
    }
    std::unique_ptr<X509_REQ, deleter<X509_REQ_free>> cert(PEM_read_bio_X509_REQ(bio.get(), nullptr, nullptr, nullptr));
    if(!cert) {
		std::runtime_error("Error reading certificate");
    }

    return cert;
}


std::unique_ptr<X509, deleter<X509_free>> x509_certificate::pem_to_x509(const std::string& pem_data) {
	std::unique_ptr<BIO, deleter<BIO_free>> bio{BIO_new_mem_buf(pem_data.data(), pem_data.size())};
    if(!bio) {
		std::runtime_error("Error creating BIO");
    }
    std::unique_ptr<X509, deleter<X509_free>> cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if(!cert) {
		std::runtime_error("Error reading certificate");
    }

    return cert;
}

std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>> x509_certificate::generate_rsa_keypair(int key_bits) {
	//Create context for key generation
	std::unique_ptr<EVP_PKEY_CTX, deleter<EVP_PKEY_CTX_free>> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
	if(!ctx) {
		std::runtime_error("Failed to create EVP_PKEY_CTX");
	}
	//Initialize key generation
	if(EVP_PKEY_keygen_init(ctx.get()) <= 0) {
		std::runtime_error("Failed to initialize key generation");
	}
	//Set RSA key length
	if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), key_bits) <= 0) {
		std::runtime_error("Failed to set RSA key length");
	}
	//Generate the key
	EVP_PKEY* pkey = nullptr;
	if(EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) {
		std::runtime_error("Failed to generate RSA key pair");
	}
	std::cout << "Successfully generated RSA-" << key_bits << " key pair\n";
	std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>> key{pkey};

	return key;
}

void x509_certificate::generate_csr(const std::string& commonName) {

   	std::unique_ptr<X509_REQ, deleter<X509_REQ_free>> cert(X509_REQ_new());
    if (!cert) {
        throw std::runtime_error("Failed to create X509_REQ");
    }
    //Set subject name
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_UTF8,
                             (const unsigned char*)"RU", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_UTF8,
                             (const unsigned char*)"playclose", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
                             (const unsigned char*)commonName.c_str(), -1, -1, 0);
    X509_REQ_set_subject_name(cert.get(), name);
    //Set public key
    X509_REQ_set_pubkey(cert.get(), key_pair_.get());
	//Sign the CSR
    if(!X509_REQ_sign(cert.get(), key_pair_.get(), EVP_sha256())) {
        throw std::runtime_error("Failed to sign CSR");
    }

	set_cert_csr(std::move(cert));	
}

std::unique_ptr<X509, deleter<X509_free>> x509_certificate::sign_csr(X509_REQ* req, int daysValid) {
    std::unique_ptr<X509, deleter<X509_free>> cert{X509_new()};
	if(!ca_cert_) {
		throw std::runtime_error("root cert is not set");
	}
	if(!key_pair_){
		throw std::runtime_error("root key is not set");
	}
    if(!cert) {
        throw std::runtime_error("Failed to create X509 certificate");
    }
    //Copy subject name from CSR
    X509_set_subject_name(cert.get(), X509_REQ_get_subject_name(req));
    //Set issuer name from CA certificate
    X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert_.get()));
    //Set public key from CSR
    std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>> pubkey{X509_REQ_get_pubkey(req)};
    X509_set_pubkey(cert.get(), pubkey.get());
    //Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), daysValid * 86400);
    //Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), rand());
    //Copy extensions from CSR
    STACK_OF(X509_EXTENSION)* req_exts = X509_REQ_get_extensions(req);
    for(int i = 0; i < sk_X509_EXTENSION_num(req_exts); i++) {
        X509_EXTENSION* ext = sk_X509_EXTENSION_value(req_exts, i);
        X509_add_ext(cert.get(), ext, -1);
    }
    sk_X509_EXTENSION_pop_free(req_exts, X509_EXTENSION_free);
    //Sign the certificate with CA private key
    if(!X509_sign(cert.get(), key_pair_.get(), EVP_sha256())) {
        throw std::runtime_error("Failed to sign certificate");
    }

    return cert;
}

void add_name_entry(X509_NAME* name, const std::string& field, const std::string& value) {
    if(!X509_NAME_add_entry_by_txt(name, field.c_str(), MBSTRING_UTF8,
                                  reinterpret_cast<const unsigned char*>(value.c_str()),
                                  -1, -1, 0)) {
        throw std::runtime_error("Failed to add name entry: " + field);
    }
}

void x509_certificate::generate_self_signed_ca(const std::string& common_name, int valid_days) {
    std::unique_ptr<X509, deleter<X509_free>> cert{X509_new()};
    if(!cert) {
        throw std::runtime_error("Failed to create X509 certificate");
    }
    //Set certificate version (X.509 v3)
    if(!X509_set_version(cert.get(), 2)) {
        throw std::runtime_error("Failed to set certificate version");
    }
    //Set serial number (random)
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), rand());
    //Set validity period
    if(!X509_gmtime_adj(X509_get_notBefore(cert.get()), 0)) {
        throw std::runtime_error("Failed to set notBefore time");
    }
    if(!X509_gmtime_adj(X509_get_notAfter(cert.get()), valid_days * 86400)) {
        throw std::runtime_error("Failed to set notAfter time");
    }
    //Set public key
    if(!X509_set_pubkey(cert.get(), key_pair_.get())) {
        throw std::runtime_error("Failed to set public key");
    }
    //Set subject name
    X509_NAME* name = X509_get_subject_name(cert.get());
    add_name_entry(name, "C", "RU");
    add_name_entry(name, "O", "SomeCompany");
    add_name_entry(name, "CN", common_name);
    //Set issuer name (self-signed)
	if(!X509_set_issuer_name(cert.get(), name)) {
        throw std::runtime_error("Failed to set issuer name");
    }
    //Add extensions
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);

    //Basic constraints
    std::unique_ptr<X509_EXTENSION, deleter<X509_EXTENSION_free>> ext{X509V3_EXT_nconf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:FALSE")};
    if(!ext || !X509_add_ext(cert.get(), ext.get(), -1)) {
        throw std::runtime_error("Failed to add basic constraints extension");
    }
    //Key usage
    ext.reset(X509V3_EXT_nconf_nid(nullptr, &ctx, NID_key_usage, "critical,digitalSignature,keyEncipherment"));
    if(!ext || !X509_add_ext(cert.get(), ext.get(), -1)) {
        throw std::runtime_error("Failed to add key usage extension");
    }
    //Sign the certificate
    if(!X509_sign(cert.get(), key_pair_.get(), EVP_sha256())) {
        throw std::runtime_error("Failed to sign certificate");
    }
	
	set_cert_ca(std::move(cert));
}

//Parse cert:
//Helper function to print ASN1_TIME
static std::string asn1_time_to_string(const ASN1_TIME* time) {
    std::unique_ptr<BIO, deleter<BIO_free>> bio(BIO_new(BIO_s_mem()));
    ASN1_TIME_print(bio.get(), time);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, len);
}

//Helper function to print X509_NAME
static std::string x509_name_to_string(X509_NAME* name) {
    std::unique_ptr<BIO, deleter<BIO_free>> bio(BIO_new(BIO_s_mem()));
    X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, len);
}

//Helper function to print public key info
static std::string public_key_info(EVP_PKEY* pkey) {
    std::unique_ptr<BIO, deleter<BIO_free>> bio(BIO_new(BIO_s_mem()));
    EVP_PKEY_print_public(bio.get(), pkey, 0, nullptr);
    char* data = nullptr;
    long len = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, len);
}

//Parse X509 certificate
//retun 0 - success, else return 1
int x509_certificate::parse_x509_ca(X509* cert, X509* cert_root) {
    if(!cert) {
        throw std::invalid_argument("Certificate cannot be null");
    }
    //Version
    std::cout << "Version: " << X509_get_version(cert) + 1 << std::endl;
    //Serial Number
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
	std::unique_ptr<BIGNUM, deleter<BN_free>> bn{ASN1_INTEGER_to_BN(serial, nullptr)};
	//TODO replace with common misc.h
    char* hex = BN_bn2hex(bn.get());
    std::cout << "Serial Number: " << hex << std::endl;
    OPENSSL_free(hex);
    //Validity
    std::cout << "Valid From: " << asn1_time_to_string(X509_get_notBefore(cert)) << std::endl;
    std::cout << "Valid Until: " << asn1_time_to_string(X509_get_notAfter(cert)) << std::endl;
    //Subject
    std::cout << "Subject: " << x509_name_to_string(X509_get_subject_name(cert)) << std::endl;
    //Issuer
    std::cout << "Issuer: " << x509_name_to_string(X509_get_issuer_name(cert)) << std::endl;
    //Public Key
	std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>> pkey;
	if(!cert_root) {
    	pkey.reset(X509_get_pubkey(cert));
    	std::cout << "Public Key:\n" << public_key_info(pkey.get()) << std::endl;
	}
	else {
		pkey.reset(X509_get_pubkey(cert_root));
    	std::cout << "Public Key:\n" << public_key_info(pkey.get()) << std::endl;
	}	
    //Extensions
    std::cout << "\nExtensions:" << std::endl;
    for(int i = 0; i < X509_get_ext_count(cert); i++) {
        X509_EXTENSION* ext = X509_get_ext(cert, i);
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
        
        char buf[256];
        OBJ_obj2txt(buf, sizeof(buf), obj, 0);
        std::cout << " - " << buf << std::endl;
    }
	if(X509_verify(cert, pkey.get())) {
		//"CA verified!"
		return 0;
	}
	//"CA verify error!"
	return 1;
}

//Parse X509 CSR
//retun 0 - success, else return 1
int x509_certificate::parse_x509_csr(X509_REQ* csr) {
    if(!csr) {
        throw std::invalid_argument("CSR cannot be null");
    }
    //Version
    std::cout << "Version: " << X509_REQ_get_version(csr) + 1 << std::endl;
    //Subject
    std::cout << "Subject: " << x509_name_to_string(X509_REQ_get_subject_name(csr)) << std::endl;
    //Public Key
    std::unique_ptr<EVP_PKEY, deleter<EVP_PKEY_free>> pkey(X509_REQ_get_pubkey(csr));
    std::cout << "Public Key:\n" << public_key_info(pkey.get()) << std::endl;
    //Signature Algorithm
	char buf[256];
    const X509_ALGOR* sig_alg;
    X509_REQ_get0_signature(csr, nullptr, &sig_alg);
    OBJ_obj2txt(buf, sizeof(buf), sig_alg->algorithm, 0);
    std::cout << "Signature Algorithm: " << buf << std::endl;
	if(X509_REQ_verify(csr, pkey.get())) {
		//"CSR verified!"
		return 0;
	}
	//"CSR verify error"
	return 1;
}

	} //namespace crypto 
} //namespace playclose
