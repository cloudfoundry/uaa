package org.cloudfoundry.identity.uaa.provider.token;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.util.StringUtils;

public class ClientAssertionHeaderAuthenticator {
    private static final Log logger = LogFactory.getLog(ClientAssertionHeaderAuthenticator.class);

    /**
     * @param clientAssertionHeader  - a JWT with 'sub' and 'tenant_id' claims for the client
     * @return 
     * @throws BadCredentialsException must throw this if authentication fails
     */
    public String authenticate(final String clientAssertionHeader, final String proxyPublicKey) throws BadCredentialsException {
        Jwt clientAssertion = null;
        try {
            if (StringUtils.hasText(clientAssertionHeader)) {
                clientAssertion = JwtHelper.decode(clientAssertionHeader);
                clientAssertion.verifySignature(new RsaVerifier(proxyPublicKey));
                return clientAssertion.getClaims();
            }
        } catch (RuntimeException e) {
            logger.debug("Validation failed for client assertion header. Header:{" + clientAssertion + "}; error: " + e);
        }

        // Do not include error detail in this exception.
        throw new BadCredentialsException("Validation of client assertion header failed.");
    }

}
