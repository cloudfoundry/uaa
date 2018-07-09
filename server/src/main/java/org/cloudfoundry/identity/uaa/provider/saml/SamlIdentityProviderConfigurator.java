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
package org.cloudfoundry.identity.uaa.provider.saml;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.apache.http.client.utils.URIBuilder;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.util.StringUtils;

import static org.springframework.util.StringUtils.hasText;

public class SamlIdentityProviderConfigurator implements InitializingBean {
    private IdentityProviderProvisioning providerProvisioning;

    public SamlIdentityProviderConfigurator() {
    }

    public List<SamlIdentityProviderDefinition> getIdentityProviderDefinitions() {
        return getIdentityProviderDefinitionsForZone(IdentityZoneHolder.get());
    }

    public List<SamlIdentityProviderDefinition> getIdentityProviderDefinitionsForZone(IdentityZone zone) {
        List<SamlIdentityProviderDefinition> result = new LinkedList<>();
        for (IdentityProvider provider : providerProvisioning.retrieveActive(zone.getId())) {
            if (OriginKeys.SAML.equals(provider.getType())) {
                result.add((SamlIdentityProviderDefinition) provider.getConfig());
            }
        }
        return result;
    }

    public List<SamlIdentityProviderDefinition> getIdentityProviderDefinitions(List<String> allowedIdps, IdentityZone zone) {
        List<SamlIdentityProviderDefinition> idpsInTheZone = getIdentityProviderDefinitionsForZone(zone);
        if (allowedIdps != null) {
            List<SamlIdentityProviderDefinition> result = new LinkedList<>();
            for (SamlIdentityProviderDefinition def : idpsInTheZone) {
                if (allowedIdps.contains(def.getIdpEntityAlias())) {
                    result.add(def);
                }
            }
            return result;
        }
        return idpsInTheZone;
    }

    /**
     * adds or replaces a SAML identity proviider
     *
     * @param providerDefinition - the provider to be added
     */
    public synchronized void validateSamlIdentityProviderDefinition(SamlIdentityProviderDefinition providerDefinition) {
        IdentityProviderMetadata added, deleted = null;
        if (providerDefinition == null) {
            throw new NullPointerException();
        }
        if (!hasText(providerDefinition.getIdpEntityAlias())) {
            throw new NullPointerException("SAML IDP Alias must be set");
        }
        if (!hasText(providerDefinition.getZoneId())) {
            throw new NullPointerException("IDP Zone Id must be set");
        }
        SamlIdentityProviderDefinition clone = providerDefinition.clone();
        added = getExtendedMetadataDelegate(clone);
        String entityIDToBeAdded = added.getEntityId();
        if (!StringUtils.hasText(entityIDToBeAdded)) {
            throw new RuntimeException("Emtpy entityID for SAML provider with zoneId:" + providerDefinition.getZoneId() + " and origin:" + providerDefinition.getIdpEntityAlias());
        }

        boolean entityIDexists = false;

        for (SamlIdentityProviderDefinition existing : getIdentityProviderDefinitions()) {
            IdentityProviderMetadata existingProvider = getExtendedMetadataDelegate(existing);
            if (entityIDToBeAdded.equals(existingProvider.getEntityId()) &&
              !(existing.getUniqueAlias().equals(clone.getUniqueAlias()))) {
                entityIDexists = true;
                break;
            }
        }

        if (entityIDexists) {
            throw new RuntimeException("Duplicate entity ID:" + entityIDToBeAdded);
        }
    }

    public IdentityProviderMetadata getExtendedMetadataDelegate(SamlIdentityProviderDefinition def)  {
        IdentityProviderMetadata metadata;
        switch (def.getType()) {
            case DATA: {
                metadata = configureXMLMetadata(def);
                break;
            }
            case URL: {
                metadata = configureURLMetadata(def);
                break;
            }
            default: {
                throw new RuntimeException("Invalid metadata type for alias[" + def.getIdpEntityAlias() + "]:" + def.getMetaDataLocation());
            }
        }
        return metadata;
    }

    protected IdentityProviderMetadata configureXMLMetadata(SamlIdentityProviderDefinition def) {
        String zoneId = def.getZoneId();
        String alias = def.getIdpEntityAlias();
        String metadata = def.getMetaDataLocation();
        IdentityProviderMetadata delegate = null;
        throw new UnsupportedOperationException();
//        configMetadataProvider.setParserPool(getParserPool());
//        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
//        extendedMetadata.setLocal(false);
//        extendedMetadata.setAlias(def.getIdpEntityAlias());
//        ExtendedMetadataDelegate delegate = new ExtendedMetadataDelegate(configMetadataProvider, extendedMetadata);
//        delegate.setMetadataTrustCheck(def.isMetadataTrustCheck());


    }


    protected String adjustURIForPort(String uri) throws URISyntaxException {
        URI metadataURI = new URI(uri);
        if (metadataURI.getPort() < 0) {
            switch (metadataURI.getScheme()) {
                case "https":
                    return new URIBuilder(uri).setPort(443).build().toString();
                case "http":
                    return new URIBuilder(uri).setPort(80).build().toString();
                default:
                    return uri;
            }
        }
        return uri;
    }

    protected IdentityProviderMetadata configureURLMetadata(SamlIdentityProviderDefinition def) {
        try {
            def = def.clone();
            String adjustedMetatadataURIForPort = adjustURIForPort(def.getMetaDataLocation());

            byte[] metadata = new byte[0];

            def.setMetaDataLocation(new String(metadata, StandardCharsets.UTF_8));
            return configureXMLMetadata(def);
        } catch (URISyntaxException e) {
            throw new RuntimeException("Invalid socket factory(invalid URI):" + def.getMetaDataLocation(), e);
        }
    }

    public IdentityProviderProvisioning getIdentityProviderProvisioning() {
        return providerProvisioning;
    }

    public void setIdentityProviderProvisioning(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }



    @Override
    public void afterPropertiesSet() throws Exception {
    }

}
