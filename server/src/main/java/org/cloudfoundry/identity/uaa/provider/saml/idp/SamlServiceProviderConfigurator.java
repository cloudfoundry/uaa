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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.util.StringUtils;

/**
 * Holds internal state of available SAML Service Providers.
 */
public class SamlServiceProviderConfigurator {
    private static final Logger LOG = LoggerFactory.getLogger(SamlServiceProviderConfigurator.class);

    private SamlServiceProviderProvisioning providerProvisioning;
    private Set<NameId> supportedNameIDs = new HashSet<>(
        Arrays.asList(
            NameId.EMAIL,
            NameId.PERSISTENT,
            NameId.UNSPECIFIED)
    );

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
                  new SamlServiceProviderHolder(provider);
                result.add(samlServiceProviderHolder);
            } catch (Exception e) {
                LOG.error("Unable to configure SAML SP Metadata for ServiceProvider:" + provider.getEntityId(), e);
            }
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * adds or replaces a SAML service provider for the current zone.
     *
     * @param provider - the provider to be added
     */
    public void validateSamlServiceProvider(SamlServiceProvider provider) {
        validateSamlServiceProvider(provider, IdentityZoneHolder.get());
    }

    synchronized void validateSamlServiceProvider(SamlServiceProvider provider, IdentityZone zone) {

        if (provider == null) {
            throw new NullPointerException();
        }
        if (!StringUtils.hasText(provider.getIdentityZoneId())) {
            throw new NullPointerException("You must set the SAML SP Identity Zone Id.");
        }
        if (!zone.getId().equals(provider.getIdentityZoneId())) {
            throw new IllegalArgumentException("The SAML SP Identity Zone Id does not match the curent zone.");
        }

        ServiceProviderMetadata added = getExtendedMetadataDelegate(provider);
        // Extract the entityId directly from the SAML metadata.
        String metadataEntityId = added.getEntityId();
        if (provider.getEntityId() == null) {
            provider.setEntityId(metadataEntityId);
        } else if (!metadataEntityId.equals(provider.getEntityId())) {
            throw new RuntimeException(
                "Metadata entity id does not match SAML SP entity id: " + provider.getEntityId()
            );
        }

        // Initializing here is necessary to access the SPSSODescriptor, otherwise an exception is thrown.
        if (null != added &&
          null != added.getServiceProvider().getNameIds() &&
          !added.getServiceProvider().getNameIds().isEmpty()) {
            // The SP explicitly states the NameID formats it supports, we should check that we support at least one.
            if (!added.getServiceProvider().getNameIds().stream().anyMatch(
              format -> this.supportedNameIDs.contains(format))) {
                throw new RuntimeException(
                  "UAA does not support any of the NameIDFormats specified in the metadata for entity: "
                    + provider.getEntityId());
            }
        }
        List<SamlServiceProviderHolder> serviceProviders = getSamlServiceProvidersForZone(zone);

    }

    public ServiceProviderMetadata getExtendedMetadataDelegate(SamlServiceProvider provider) {
        ServiceProviderMetadata metadata;
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
                throw new RuntimeException("Invalid metadata type for alias[" + provider.getEntityId() + "]:"
                  + provider.getConfig().getMetaDataLocation());
            }
        }
        return metadata;
    }

    protected ServiceProviderMetadata configureXMLMetadata(SamlServiceProvider provider) {
//        ConfigMetadataProvider configMetadataProvider = new ConfigMetadataProvider(provider.getIdentityZoneId(),
//          provider.getEntityId(), provider.getConfig().getMetaDataLocation());
//        configMetadataProvider.setParserPool(getParserPool());
//        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
//        extendedMetadata.setLocal(false);
//        extendedMetadata.setAlias(provider.getEntityId());
//        ExtendedMetadataDelegate delegate = new ExtendedMetadataDelegate(configMetadataProvider, extendedMetadata);
//        delegate.setMetadataTrustCheck(provider.getConfig().isMetadataTrustCheck());

        throw new UnsupportedOperationException();
    }

    protected ServiceProviderMetadata configureURLMetadata(SamlServiceProvider provider) throws RuntimeException {
        throw new UnsupportedOperationException();
    }

    public SamlServiceProviderProvisioning getProviderProvisioning() {
        return providerProvisioning;
    }

    public void setProviderProvisioning(SamlServiceProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    public void setSupportedNameIDs(Set<NameId> supportedNameIDs) {
        this.supportedNameIDs = supportedNameIDs;
    }

}
