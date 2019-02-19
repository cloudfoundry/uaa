package org.cloudfoundry.identity.uaa.oauth.jwt;

public interface Signer extends org.springframework.security.jwt.crypto.sign.Signer {
    String keyId();
    String keyURL();
}
