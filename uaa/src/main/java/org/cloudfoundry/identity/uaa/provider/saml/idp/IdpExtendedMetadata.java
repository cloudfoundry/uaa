/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.springframework.security.saml.metadata.ExtendedMetadata;

/**
 * A SAML IdP needs information beyond what the standard ExtendedMetadata provides.
 * This class exists to provide that extra information.
 */
public class IdpExtendedMetadata extends ExtendedMetadata {

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
