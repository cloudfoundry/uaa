package org.cloudfoundry.identity.uaa.oauth.jwt;


import org.junit.Test;

public class CommonSignatureVerifierTest {

    @Test(expected = IllegalArgumentException.class)
    public void null_is_not_an_acceptable_key() {
        new CommonSignatureVerifier(null);
    }

}