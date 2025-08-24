package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.JWSSigner;

public interface Signer extends JWSSigner {
    String keyId();

    String keyURL();
}
