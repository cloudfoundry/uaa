package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.springframework.security.saml.util.SAMLUtil;

public class ZoneAwareIdpMetadataGenerator extends IdpMetadataGenerator {

    @Override
    public boolean isAssertionsSigned() {
        if (!IdentityZoneHolder.isUaa()) {
            return getZoneDefinition().getSamlConfig().isAssertionSigned();
        }
        return super.isAssertionsSigned();
    }

    @Override
    public int getAssertionTimeToLiveSeconds() {
        if (!IdentityZoneHolder.isUaa()) {
            return getZoneDefinition().getSamlConfig().getAssertionTimeToLiveSeconds();
        }
        return super.getAssertionTimeToLiveSeconds();
    }

    @Override
    public IdpExtendedMetadata generateExtendedMetadata() {
        IdpExtendedMetadata metadata = super.generateExtendedMetadata();
        metadata.setAlias(UaaUrlUtils.getSubdomain() + metadata.getAlias());
        return metadata;
    }

    @Override
    public String getEntityId() {
        String entityId = super.getEntityId();
        if (UaaUrlUtils.isUrl(entityId)) {
            return UaaUrlUtils.addSubdomainToUrl(entityId);
        } else {
            return UaaUrlUtils.getSubdomain() + entityId;
        }
    }

    @Override
    public String getEntityBaseURL() {
        return UaaUrlUtils.addSubdomainToUrl(super.getEntityBaseURL());
    }

    @Override
    protected String getEntityAlias() {
        return UaaUrlUtils.getSubdomain() + super.getEntityAlias();
    }

    @Override
    public boolean isWantAuthnRequestSigned() {
        if (!IdentityZoneHolder.isUaa()) {
            return getZoneDefinition().getSamlConfig().isWantAuthnRequestSigned();
        }
        return super.isWantAuthnRequestSigned();
    }

    protected IdentityZoneConfiguration getZoneDefinition() {
        IdentityZone zone = IdentityZoneHolder.get();
        IdentityZoneConfiguration definition = zone.getConfig();
        return definition != null ? definition : new IdentityZoneConfiguration();
    }

    @Override
    public EntityDescriptor generateMetadata() {
        EntityDescriptor result = super.generateMetadata();
        result.setID(SAMLUtil.getNCNameString(result.getEntityID()));
        return result;
    }
}
