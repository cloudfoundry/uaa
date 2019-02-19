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

import org.apache.http.client.utils.URIBuilder;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;

import static org.springframework.util.StringUtils.hasText;

public class SamlIdentityProviderConfigurator implements InitializingBean {
    private BasicParserPool parserPool;
    private IdentityProviderProvisioning providerProvisioning;
    private FixedHttpMetaDataProvider fixedHttpMetaDataProvider;

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
     * @throws MetadataProviderException if the system fails to fetch meta data for this provider
     */
    public synchronized void validateSamlIdentityProviderDefinition(SamlIdentityProviderDefinition providerDefinition) throws MetadataProviderException {
        ExtendedMetadataDelegate added, deleted = null;
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
        String entityIDToBeAdded = ((ConfigMetadataProvider) added.getDelegate()).getEntityID();
        if (!StringUtils.hasText(entityIDToBeAdded)) {
            throw new MetadataProviderException("Emtpy entityID for SAML provider with zoneId:" + providerDefinition.getZoneId() + " and origin:" + providerDefinition.getIdpEntityAlias());
        }

        boolean entityIDexists = false;

        for (SamlIdentityProviderDefinition existing : getIdentityProviderDefinitions()) {
            ConfigMetadataProvider existingProvider = (ConfigMetadataProvider) getExtendedMetadataDelegate(existing).getDelegate();
            if (entityIDToBeAdded.equals(existingProvider.getEntityID()) &&
              !(existing.getUniqueAlias().equals(clone.getUniqueAlias()))) {
                entityIDexists = true;
                break;
            }
        }

        if (entityIDexists) {
            throw new MetadataProviderException("Duplicate entity ID:" + entityIDToBeAdded);
        }
    }

    public ExtendedMetadataDelegate getExtendedMetadataDelegateFromCache(SamlIdentityProviderDefinition def) throws MetadataProviderException {
        return getExtendedMetadataDelegate(def);
    }

    public ExtendedMetadataDelegate getExtendedMetadataDelegate(SamlIdentityProviderDefinition def) throws MetadataProviderException {
        ExtendedMetadataDelegate metadata;
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
                throw new MetadataProviderException("Invalid metadata type for alias[" + def.getIdpEntityAlias() + "]:" + def.getMetaDataLocation());
            }
        }
        return metadata;
    }

    protected ExtendedMetadataDelegate configureXMLMetadata(SamlIdentityProviderDefinition def) {
        ConfigMetadataProvider configMetadataProvider = new ConfigMetadataProvider(def.getZoneId(), def.getIdpEntityAlias(), def.getMetaDataLocation());
        configMetadataProvider.setParserPool(getParserPool());
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setLocal(false);
        extendedMetadata.setAlias(def.getIdpEntityAlias());
        ExtendedMetadataDelegate delegate = new ExtendedMetadataDelegate(configMetadataProvider, extendedMetadata);
        delegate.setMetadataTrustCheck(def.isMetadataTrustCheck());

        return delegate;
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

    protected ExtendedMetadataDelegate configureURLMetadata(SamlIdentityProviderDefinition def) throws MetadataProviderException {
        try {
            def = def.clone();
            String adjustedMetatadataURIForPort = adjustURIForPort(def.getMetaDataLocation());

            byte[] metadata = fixedHttpMetaDataProvider.fetchMetadata(adjustedMetatadataURIForPort, def.isSkipSslValidation());

            def.setMetaDataLocation(new String(metadata, StandardCharsets.UTF_8));
            return configureXMLMetadata(def);
        } catch (URISyntaxException e) {
            throw new MetadataProviderException("Invalid socket factory(invalid URI):" + def.getMetaDataLocation(), e);
        }
    }

    public IdentityProviderProvisioning getIdentityProviderProvisioning() {
        return providerProvisioning;
    }

    public void setIdentityProviderProvisioning(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }


    public BasicParserPool getParserPool() {
        return parserPool;
    }

    public void setParserPool(BasicParserPool parserPool) {
        this.parserPool = parserPool;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
    }

    public void setFixedHttpMetaDataProvider(FixedHttpMetaDataProvider fixedHttpMetaDataProvider) {
        this.fixedHttpMetaDataProvider = fixedHttpMetaDataProvider;
    }
}
