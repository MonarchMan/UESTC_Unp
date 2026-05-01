#pragma once

#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <string>

namespace quic {

// Initialize global GnuTLS state for QUIC.
bool init_crypto_global();

// Deinitialize global GnuTLS state.
void deinit_crypto_global();

// Load server credentials (cert + key).
gnutls_certificate_credentials_t load_server_credentials(const std::string& cert_path,
                                                            const std::string& key_path);

// Create a GnuTLS client session configured for QUIC.
// |ca_cert_path| is an optional path to a CA certificate to trust (for self-signed certs).
// |out_cred| receives allocated credentials that must be freed with
// gnutls_certificate_free_credentials.
gnutls_session_t create_client_session(const std::string& ca_cert_path,
                                        gnutls_certificate_credentials_t* out_cred);

// Create a GnuTLS server session configured for QUIC.
gnutls_session_t create_server_session(gnutls_certificate_credentials_t cred);

} // namespace quic
