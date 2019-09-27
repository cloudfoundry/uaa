/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.provider.saml.ConfigMetadataProvider;
import org.cloudfoundry.identity.uaa.provider.saml.FixedHttpMetaDataProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Holds internal state of available SAML Service Providers.
 */
public class SamlServiceProviderConfigurator {
    private static final Logger LOG = LoggerFactory.getLogger(SamlServiceProviderConfigurator.class);

    private FixedHttpMetaDataProvider fixedHttpMetaDataProvider;
    private BasicParserPool parserPool;
    private SamlServiceProviderProvisioning providerProvisioning;
    private Set<String> supportedNameIDs = new HashSet<>(Arrays.asList(NameIDType.EMAIL, NameIDType.PERSISTENT, NameIDType.UNSPECIFIED));

    public SamlServiceProviderConfigurator() {
    }

    public List<SamlServiceProviderHolder> getSamlServiceProviders() {
        return getSamlServiceProvidersForZone(IdentityZoneHolder.get());
    }

    public List<SamlServiceProviderHolder> getSamlServiceProvidersForZone(IdentityZone zone) {
        List<SamlServiceProviderHolder> result = new LinkedList<>();
        for (SamlServiceProvider provider : providerProvisioning.retrieveActive(zone.getId())) {
            try {
                SamlServiceProviderHolder samlServiceProviderHolder =
                  new SamlServiceProviderHolder(getExtendedMetadataDelegate(provider), provider);
                result.add(samlServiceProviderHolder);
            } catch (MetadataProviderException e) {
                LOG.error("Unable to configure SAML SP Metadata for ServiceProvider:" + provider.getEntityId(), e);
            }
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * adds or replaces a SAML service provider for the current zone.
     *
     * @param provider - the provider to be added
     * @throws MetadataProviderException if the system fails to fetch meta data for this provider
     */
    public void validateSamlServiceProvider(SamlServiceProvider provider) throws MetadataProviderException {
        validateSamlServiceProvider(provider, IdentityZoneHolder.get());
    }

    synchronized void validateSamlServiceProvider(SamlServiceProvider provider, IdentityZone zone)
      throws MetadataProviderException {

        if (provider == null) {
            throw new NullPointerException();
        }
        if (!StringUtils.hasText(provider.getIdentityZoneId())) {
            throw new NullPointerException("You must set the SAML SP Identity Zone Id.");
        }
        if (!zone.getId().equals(provider.getIdentityZoneId())) {
            throw new IllegalArgumentException("The SAML SP Identity Zone Id does not match the curent zone.");
        }

        ExtendedMetadataDelegate added = getExtendedMetadataDelegate(provider);
        // Extract the entityId directly from the SAML metadata.
        String metadataEntityId = ((ConfigMetadataProvider) added.getDelegate()).getEntityID();
        if (provider.getEntityId() == null) {
            provider.setEntityId(metadataEntityId);
        } else if (!metadataEntityId.equals(provider.getEntityId())) {
            throw new MetadataProviderException(
              "Metadata entity id does not match SAML SP entity id: " + provider.getEntityId());
        }

        // Initializing here is necessary to access the SPSSODescriptor, otherwise an exception is thrown.
        added.initialize();
        SPSSODescriptor spSsoDescriptor = added.getEntityDescriptor(metadataEntityId).
          getSPSSODescriptor(SAMLConstants.SAML20P_NS);
        if (null != spSsoDescriptor &&
          null != spSsoDescriptor.getNameIDFormats() &&
          !spSsoDescriptor.getNameIDFormats().isEmpty()) {
            // The SP explicitly states the NameID formats it supports, we should check that we support at least one.
            if (spSsoDescriptor.getNameIDFormats().stream().noneMatch(
              format -> this.supportedNameIDs.contains(format.getFormat()))) {
                throw new MetadataProviderException(
                  "UAA does not support any of the NameIDFormats specified in the metadata for entity: "
                    + provider.getEntityId());
            }
        }
        List<SamlServiceProviderHolder> serviceProviders = getSamlServiceProvidersForZone(zone);

    }

    public ExtendedMetadataDelegate getExtendedMetadataDelegate(SamlServiceProvider provider)
      throws MetadataProviderException {
        ExtendedMetadataDelegate metadata;
        switch (provider.getConfig().getType()) {
            case DATA: {
                metadata = configureXMLMetadata(provider);
                break;
            }
            case URL: {
                metadata = configureURLMetadata(provider);
                break;
            }
            default: {
                throw new MetadataProviderException("Invalid metadata type for alias[" + provider.getEntityId() + "]:"
                  + provider.getConfig().getMetaDataLocation());
            }
        }
        return metadata;
    }

    protected ExtendedMetadataDelegate configureXMLMetadata(SamlServiceProvider provider) {
        ConfigMetadataProvider configMetadataProvider = new ConfigMetadataProvider(provider.getIdentityZoneId(),
          provider.getEntityId(), provider.getConfig().getMetaDataLocation());
        configMetadataProvider.setParserPool(getParserPool());
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setLocal(false);
        extendedMetadata.setAlias(provider.getEntityId());
        ExtendedMetadataDelegate delegate = new ExtendedMetadataDelegate(configMetadataProvider, extendedMetadata);
        delegate.setMetadataTrustCheck(provider.getConfig().isMetadataTrustCheck());

        return delegate;
    }

    protected ExtendedMetadataDelegate configureURLMetadata(SamlServiceProvider provider)
      throws MetadataProviderException {
        SamlServiceProviderDefinition def = provider.getConfig().clone();
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setAlias(provider.getEntityId());
        byte[] metadata;
        try {
            metadata = fixedHttpMetaDataProvider.fetchMetadata(def.getMetaDataLocation(), def.isSkipSslValidation());
        } catch (RestClientException e) {
            throw new MetadataProviderException("Unavailable Metadata Provider", e);
        }
        def.setMetaDataLocation(new String(metadata, StandardCharsets.UTF_8));
        return configureXMLMetadata(provider);
    }

    public SamlServiceProviderProvisioning getProviderProvisioning() {
        return providerProvisioning;
    }

    public void setProviderProvisioning(SamlServiceProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    public BasicParserPool getParserPool() {
        return parserPool;
    }

    public void setParserPool(BasicParserPool parserPool) {
        this.parserPool = parserPool;
    }

    public void setSupportedNameIDs(Set<String> supportedNameIDs) {
        this.supportedNameIDs = supportedNameIDs;
    }

    public void setFixedHttpMetaDataProvider(FixedHttpMetaDataProvider fixedHttpMetaDataProvider) {
        this.fixedHttpMetaDataProvider = fixedHttpMetaDataProvider;
    }
}
