package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.springframework.security.saml.metadata.ExtendedMetadata;

/**
 * A SAML IdP needs information beyond what the standard ExtendedMetadata provides.
 * This class exists to provide that extra information.
 */
public class IdpExtendedMetadata extends ExtendedMetadata {

    /**
     * Generated serialization id.
     */
    private static final long serialVersionUID = -7933870052729540864L;

    private boolean assertionsSigned = true;
    private int assertionTimeToLiveSeconds = 500;

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

    @Override
    public IdpExtendedMetadata clone() {
        return (IdpExtendedMetadata) super.clone();
    }
}
