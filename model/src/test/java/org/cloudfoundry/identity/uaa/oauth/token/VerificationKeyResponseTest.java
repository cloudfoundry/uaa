package org.cloudfoundry.identity.uaa.oauth.token;

import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.jwk.JWKParameterNames;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class VerificationKeyResponseTest {

    private VerificationKeyResponse verificationKeyResponse;

    void setupResponse(String kty, String x5t, String x5c) {
        HashMap hashMap = new HashMap<>();
        if (kty != null) {
            hashMap.put(JWKParameterNames.KEY_TYPE, kty);
        }
        if (x5t != null) {
            hashMap.put(HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT, x5t);
        }
        if (x5c != null) {
            hashMap.put(HeaderParameterNames.X_509_CERT_CHAIN, Arrays.asList(x5c).toArray(new String[0]));
        }
        verificationKeyResponse = new VerificationKeyResponse(hashMap);
    }

    @Test
    void x509CertificateSet() {
        setupResponse("RSA", null, "certificate");
        assertThat(verificationKeyResponse.getCertX5c()[0]).isEqualTo("certificate");
    }

    @Test
    void x509ThumbPrintSet() {
        setupResponse("RSA", "thumbprint", null);
        assertThat(verificationKeyResponse.getCertX5t()).isEqualTo("thumbprint");
    }

    @Test
    void keyTypeNullException() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> setupResponse(null, "thumbprint", "certificate"));
    }

    @Test
    void verificationKeyResponse() {
        setupResponse("RSA", "thumbprint", "certificate");
        assertThat(verificationKeyResponse.getKty()).isEqualTo(JsonWebKey.KeyType.valueOf("RSA"));
        assertThat(verificationKeyResponse.getX5t()).isEqualTo("thumbprint");
        assertThat(verificationKeyResponse.getCertX5c()[0]).isEqualTo("certificate");
    }
}
