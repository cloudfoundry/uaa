package org.cloudfoundry.identity.uaa.provider.token;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.security.authentication.BadCredentialsException;

public class ClientAssertionHeaderAuthenticatorTest {
    private final static String TENANT_ID = "t10";
    private final static String ISSUER_ID = "d10";

    @Test
    public void testSuccess() {
        try {
            String header = new MockClientAssertionHeader().mockSignedHeader(ISSUER_ID, TENANT_ID);
            ClientAssertionHeaderAuthenticator headerAuthenticator = new ClientAssertionHeaderAuthenticator();
            headerAuthenticator.authenticate(header, TestKeys.TOKEN_VERIFYING_KEY);
        } catch (Exception e) {
            Assert.fail("Failed to authenticate client assertion header. " + e.getMessage());
        }
    }

    @Test
    public void testFail() {
        try {
            String header = new MockClientAssertionHeader().mockIncorrectlySignedHeader(ISSUER_ID, TENANT_ID);
            ClientAssertionHeaderAuthenticator headerAuthenticator = new ClientAssertionHeaderAuthenticator();
            headerAuthenticator.authenticate(header, TestKeys.TOKEN_VERIFYING_KEY);
            Assert.fail("Succeeded to authenticate incorrectly signed client assertion header.");
        } catch (BadCredentialsException bce) {
        } catch (Exception e) {
            Assert.fail("Validation of client assertion header failed for unexpected reason.");
        }
    }
}
