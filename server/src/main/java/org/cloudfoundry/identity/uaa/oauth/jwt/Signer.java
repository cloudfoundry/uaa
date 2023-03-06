package org.cloudfoundry.identity.uaa.oauth.jwt;

public interface Signer {
    String keyId();
    String keyURL();
    byte[] sign(byte[] bytes);
}
