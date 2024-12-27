package org.cloudfoundry.identity.uaa.oauth.token;

import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.jwk.JWKParameterNames;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
    void testX509CertificateSet() {
        setupResponse("RSA", null, "certificate");
        assertEquals("certificate", verificationKeyResponse.getCertX5c()[0]);
    }

    @Test
    void testX509ThumbPrintSet() {
        setupResponse("RSA", "thumbprint", null);
        assertEquals("thumbprint", verificationKeyResponse.getCertX5t());
    }

    @Test
    void testKeyTypeNullException() {
        assertThrows(IllegalArgumentException.class, () -> setupResponse(null, "thumbprint", "certificate"));
    }

    @Test
    void testVerificationKeyResponse() {
        setupResponse("RSA", "thumbprint", "certificate");
        assertEquals(JsonWebKey.KeyType.valueOf("RSA"), verificationKeyResponse.getKty());
        assertEquals("thumbprint", verificationKeyResponse.getX5t());
        assertEquals("certificate", verificationKeyResponse.getCertX5c()[0]);
    }
}
