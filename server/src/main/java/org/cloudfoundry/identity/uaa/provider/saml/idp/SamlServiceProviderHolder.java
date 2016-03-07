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

import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

public class SamlServiceProviderHolder {

    private final ExtendedMetadataDelegate extendedMetadataDelegate;
    private final SamlServiceProvider samlServiceProvider;

    public SamlServiceProviderHolder(ExtendedMetadataDelegate extendedMetadataDelegate,
            SamlServiceProvider samlServiceProvider) {

        this.extendedMetadataDelegate = extendedMetadataDelegate;
        this.samlServiceProvider = samlServiceProvider;
    }

    public ExtendedMetadataDelegate getExtendedMetadataDelegate() {
        return extendedMetadataDelegate;
    }

    public SamlServiceProvider getSamlServiceProvider() {
        return samlServiceProvider;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((samlServiceProvider.getIdentityZoneId() == null) ? 0 : samlServiceProvider.getIdentityZoneId().hashCode());
        result = prime * result + ((samlServiceProvider.getEntityId() == null) ? 0 : samlServiceProvider.getEntityId().hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        SamlServiceProviderHolder other = (SamlServiceProviderHolder) obj;
        if (samlServiceProvider.getIdentityZoneId() == null) {
            if (other.samlServiceProvider.getIdentityZoneId() != null)
                return false;
        } else if (!samlServiceProvider.getIdentityZoneId().equals(other.samlServiceProvider.getIdentityZoneId()))
            return false;
        if (samlServiceProvider.getEntityId() == null) {
            if (other.samlServiceProvider.getEntityId() != null)
                return false;
        } else if (!samlServiceProvider.getEntityId().equals(other.samlServiceProvider.getEntityId()))
            return false;
        return true;
    }

}
