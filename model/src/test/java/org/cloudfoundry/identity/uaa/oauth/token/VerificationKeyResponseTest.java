package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VerificationKeyResponseTest {

  private VerificationKeyResponse verificationKeyResponse;
  @BeforeEach
  void setup() {
    HashMap hashMap = new HashMap<>();
    hashMap.put(JsonWebKey.KTY, "RSA");
    hashMap.put(JsonWebKey.X5T, "thumbprint");
    hashMap.put(JsonWebKey.X5C, Arrays.asList("cert").toArray(new String[0]));
    verificationKeyResponse = new VerificationKeyResponse(hashMap);
  }

  @Test
  void getCertX5c() {
    assertEquals("cert", verificationKeyResponse.getCertX5c()[0]);
  }

  @Test
  void getCertX5t() {
    assertEquals("thumbprint", verificationKeyResponse.getCertX5t());
  }
}