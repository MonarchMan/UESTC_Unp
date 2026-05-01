#include "quic_crypto.hpp"
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <iostream>

namespace quic {

bool init_crypto_global() {
    gnutls_global_set_log_level(0);
    int ret = gnutls_global_init();
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "gnutls_global_init failed: " << gnutls_strerror(ret) << std::endl;
        return false;
    }
    return true;
}

void deinit_crypto_global() {
    gnutls_global_deinit();
}

gnutls_certificate_credentials_t load_server_credentials(const std::string& cert_path,
                                                            const std::string& key_path) {
    gnutls_certificate_credentials_t cred = nullptr;
    int ret = gnutls_certificate_allocate_credentials(&cred);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "gnutls_certificate_allocate_credentials failed" << std::endl;
        return nullptr;
    }
    ret = gnutls_certificate_set_x509_key_file(cred, cert_path.c_str(), key_path.c_str(),
                                                GNUTLS_X509_FMT_PEM);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "gnutls_certificate_set_x509_key_file failed: " << gnutls_strerror(ret) << std::endl;
        gnutls_certificate_free_credentials(cred);
        return nullptr;
    }
    return cred;
}

gnutls_session_t create_client_session(const std::string& ca_cert_path,
                                        gnutls_certificate_credentials_t* out_cred) {
    gnutls_session_t session = nullptr;
    int ret = gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_NO_END_OF_EARLY_DATA);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "gnutls_init failed" << std::endl;
        return nullptr;
    }

    // Priority before ngtcp2 configure (order from ngtcp2 examples).
    const char* priorities = "%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM";
    ret = gnutls_priority_set_direct(session, priorities, nullptr);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "gnutls_priority_set_direct failed: " << gnutls_strerror(ret) << std::endl;
        gnutls_deinit(session);
        return nullptr;
    }

    // ngtcp2 configure before credentials_set (order from ngtcp2 examples).
    ret = ngtcp2_crypto_gnutls_configure_client_session(session);
    if (ret != 0) {
        std::cerr << "ngtcp2_crypto_gnutls_configure_client_session failed" << std::endl;
        gnutls_deinit(session);
        return nullptr;
    }

    gnutls_certificate_credentials_t cred = nullptr;
    ret = gnutls_certificate_allocate_credentials(&cred);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "gnutls_certificate_allocate_credentials failed" << std::endl;
        gnutls_deinit(session);
        return nullptr;
    }

    if (!ca_cert_path.empty()) {
        ret = gnutls_certificate_set_x509_trust_file(cred, ca_cert_path.c_str(),
                                                      GNUTLS_X509_FMT_PEM);
        if (ret < 0) {
            std::cerr << "gnutls_certificate_set_x509_trust_file failed: "
                      << gnutls_strerror(ret) << std::endl;
        }
    }

    // Disable certificate verification for testing (self-signed certs).
    gnutls_certificate_set_verify_function(cred, [](gnutls_session_t) -> int { return 0; });

    ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "gnutls_credentials_set failed" << std::endl;
        gnutls_certificate_free_credentials(cred);
        gnutls_deinit(session);
        return nullptr;
    }

    // QUIC requires ALPN negotiation.
    {
        gnutls_datum_t alpn = {const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("\x04quic")), 5};
        gnutls_alpn_set_protocols(session, &alpn, 1, 0);
    }

    *out_cred = cred;
    return session;
}

gnutls_session_t create_server_session(gnutls_certificate_credentials_t cred) {
    if (!cred) return nullptr;
    gnutls_session_t session = nullptr;
    int ret = gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NO_END_OF_EARLY_DATA);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "gnutls_init failed" << std::endl;
        return nullptr;
    }

    const char* priorities = "%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM";
    ret = gnutls_priority_set_direct(session, priorities, nullptr);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "gnutls_priority_set_direct failed: " << gnutls_strerror(ret) << std::endl;
        gnutls_deinit(session);
        return nullptr;
    }

    ret = ngtcp2_crypto_gnutls_configure_server_session(session);
    if (ret != 0) {
        std::cerr << "ngtcp2_crypto_gnutls_configure_server_session failed" << std::endl;
        gnutls_deinit(session);
        return nullptr;
    }

    ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
    if (ret != GNUTLS_E_SUCCESS) {
        std::cerr << "gnutls_credentials_set failed" << std::endl;
        gnutls_deinit(session);
        return nullptr;
    }

    // QUIC requires ALPN negotiation
    {
        gnutls_datum_t alpn = {const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("\x04quic")), 5};
        gnutls_alpn_set_protocols(session, &alpn, 1, 0);
    }

    return session;
}

} // namespace quic
