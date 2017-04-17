/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.security.credential.UsageType;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.util.SAMLUtil;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class ZoneAwareMetadataGenerator extends MetadataGenerator {

    @Override
    public ExtendedMetadata generateExtendedMetadata() {
        ExtendedMetadata metadata = super.generateExtendedMetadata();
        metadata.setAlias(UaaUrlUtils.getSubdomain()+metadata.getAlias());
        return metadata;
    }

    @Override
    public String getEntityId() {
        String entityId = super.getEntityId();
        if (UaaUrlUtils.isUrl(entityId)) {
            return UaaUrlUtils.addSubdomainToUrl(entityId);
        } else {
            return UaaUrlUtils.getSubdomain()+entityId;
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
    public boolean isRequestSigned() {
        if (!IdentityZoneHolder.isUaa()) {
            return getZoneDefinition().getSamlConfig().isRequestSigned();
        }
        return super.isRequestSigned();
    }

    @Override
    public boolean isWantAssertionSigned() {
        if (!IdentityZoneHolder.isUaa()) {
            return getZoneDefinition().getSamlConfig().isWantAssertionSigned();
        }
        return super.isWantAssertionSigned();
    }

    protected IdentityZoneConfiguration getZoneDefinition() {
        IdentityZone zone = IdentityZoneHolder.get();
        IdentityZoneConfiguration definition = zone.getConfig();
        return definition!=null ? definition : new IdentityZoneConfiguration();
    }

    @Override
    public EntityDescriptor generateMetadata() {
        EntityDescriptor result = super.generateMetadata();
        result.setID(SAMLUtil.getNCNameString(result.getEntityID()));
        return result;
    }

    @Override
    protected SPSSODescriptor buildSPSSODescriptor(String entityBaseURL, String entityAlias, boolean requestSigned, boolean wantAssertionSigned, Collection<String> includedNameID) {
        SPSSODescriptor result = super.buildSPSSODescriptor(entityBaseURL, entityAlias, requestSigned, wantAssertionSigned, includedNameID);

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

        int index = result.getAssertionConsumerServices().size();
        result.getAssertionConsumerServices()
            .add(
                getAssertionConsumerService(
                    getEntityBaseURL(),
                    getEntityAlias(),
                    false,
                    index,
                    "/oauth/token",
                    "urn:oasis:names:tc:SAML:2.0:bindings:URI"
                ));
        return result;
    }

}
