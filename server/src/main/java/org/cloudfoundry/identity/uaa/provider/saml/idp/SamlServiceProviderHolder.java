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
