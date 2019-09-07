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

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.xml.security.credential.UsageType;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

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
        metadata.setAlias(UaaUrlUtils.getSubdomain(IdentityZoneHolder.get().getSubdomain()) + metadata.getAlias());
        return metadata;
    }

    @Override
    public String getEntityId() {
        String entityId = super.getEntityId();
        if(StringUtils.hasText(IdentityZoneHolder.get().getConfig().getSamlConfig().getEntityID())) {
            return IdentityZoneHolder.get().getConfig().getSamlConfig().getEntityID();
        } else if (UaaUrlUtils.isUrl(entityId)) {
            return UaaUrlUtils.addSubdomainToUrl(entityId, IdentityZoneHolder.get().getSubdomain());
        } else {
            return UaaUrlUtils.getSubdomain(IdentityZoneHolder.get().getSubdomain()) + entityId;
        }
    }

    @Override
    public String getEntityBaseURL() {
        return UaaUrlUtils.addSubdomainToUrl(super.getEntityBaseURL(), IdentityZoneHolder.get().getSubdomain());
    }

    @Override
    protected String getEntityAlias() {
        return UaaUrlUtils.getSubdomain(IdentityZoneHolder.get().getSubdomain()) + super.getEntityAlias();
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

    @Override
    protected IDPSSODescriptor buildIDPSSODescriptor(String entityBaseURL, String entityAlias, boolean wantAuthnRequestSigned, Collection<String> includedNameID) {
        IDPSSODescriptor result = super.buildIDPSSODescriptor(entityBaseURL, entityAlias, wantAuthnRequestSigned, includedNameID);
        //metadata should not contain inactive keys
        KeyManager samlSPKeyManager = IdentityZoneHolder.getSamlSPKeyManager();
        if (samlSPKeyManager != null && samlSPKeyManager.getAvailableCredentials()!=null) {
            Set<String> allKeyAliases = new HashSet(samlSPKeyManager.getAvailableCredentials());
            String activeKeyAlias = samlSPKeyManager.getDefaultCredentialName();
            allKeyAliases.remove(activeKeyAlias);
            for (String keyAlias : allKeyAliases) {
                result.getKeyDescriptors().add(getKeyDescriptor(UsageType.SIGNING, getServerKeyInfo(keyAlias)));
            }
        }//add inactive keys as signing verification keys
        return result;
    }
}
