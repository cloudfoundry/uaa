
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.springframework.security.saml.websso.WebSSOProfileOptions;

/**
 * DTO for SAML IdP Web SSO Profile options.
 */
public class IdpWebSSOProfileOptions extends WebSSOProfileOptions {

    /**
     * Generated serialization id.
     */
    private static final long serialVersionUID = 531377853538365709L;

    private boolean assertionsSigned;
    private int assertionTimeToLiveSeconds;

    public boolean isAssertionsSigned() {
        return assertionsSigned;
    }

    public void setAssertionsSigned(boolean assertionsSigned) {
        this.assertionsSigned = assertionsSigned;
    }

    public int getAssertionTimeToLiveSeconds() {
        return assertionTimeToLiveSeconds;
    }

    public void setAssertionTimeToLiveSeconds(int assertionTimeToLiveSeconds) {
        this.assertionTimeToLiveSeconds = assertionTimeToLiveSeconds;
    }
}
