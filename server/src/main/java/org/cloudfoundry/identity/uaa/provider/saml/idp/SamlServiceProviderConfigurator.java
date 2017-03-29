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

import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.utils.URIBuilder;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.provider.saml.ConfigMetadataProvider;
import org.cloudfoundry.identity.uaa.provider.saml.FixedHttpMetaDataProvider;
import org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.*;

/**
 * Holds internal state of available SAML Service Providers.
 */
public class SamlServiceProviderConfigurator {
    private static final Log logger = LogFactory.getLog(SamlServiceProviderConfigurator.class);

    private HttpClientParams clientParams;
    private BasicParserPool parserPool;


    private SamlServiceProviderProvisioning providerProvisioning;

    private Set<String> supportedNameIDs = new HashSet<>(Arrays.asList(NameIDType.EMAIL, NameIDType.PERSISTENT,
            NameIDType.UNSPECIFIED));
    private UrlContentCache contentCache;

    private Timer dummyTimer = new Timer() {

        @Override
        public void cancel() {
            super.cancel();
        }

        @Override
        public int purge() {
            return 0;
        }

        @Override
        public void schedule(TimerTask task, long delay) {
            // Do nothing.
        }

        @Override
        public void schedule(TimerTask task, long delay, long period) {
            // Do nothing.
        }

        @Override
        public void schedule(TimerTask task, Date firstTime, long period) {
            // Do nothing.
        }

        @Override
        public void schedule(TimerTask task, Date time) {
            // Do nothing.
        }

        @Override
        public void scheduleAtFixedRate(TimerTask task, long delay, long period) {
            // Do nothing.
        }

        @Override
        public void scheduleAtFixedRate(TimerTask task, Date firstTime, long period) {
            // Do nothing.
        }
    };

    public UrlContentCache getContentCache() {
        return contentCache;
    }

    public SamlServiceProviderConfigurator setContentCache(UrlContentCache contentCache) {
        this.contentCache = contentCache;
        return this;
    }

    public SamlServiceProviderConfigurator() {
        dummyTimer.cancel();
    }

    public List<SamlServiceProviderHolder> getSamlServiceProviders() {
        return getSamlServiceProvidersForZone(IdentityZoneHolder.get());
    }

    public List<SamlServiceProviderHolder> getSamlServiceProvidersForZone(IdentityZone zone) {
        List<SamlServiceProviderHolder> result = new LinkedList<>();
        for (SamlServiceProvider provider: providerProvisioning.retrieveActive(zone.getId())) {
            try {
                SamlServiceProviderHolder samlServiceProviderHolder =
                        new SamlServiceProviderHolder(getExtendedMetadataDelegate(provider), provider);
                result.add(samlServiceProviderHolder);
            }catch(MetadataProviderException e) {
                logger.error("Unable to configure SAML SP Metadata for ServiceProvider:" + provider.getEntityId(), e);
            }
        }
        return Collections.unmodifiableList(result);
    }

    /**
     * adds or replaces a SAML service provider for the current zone.
     *
     * @param provider
     *            - the provider to be added
     * @throws MetadataProviderException
     *             if the system fails to fetch meta data for this provider
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
        }
        else if (!metadataEntityId.equals(provider.getEntityId())) {
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
            if (!spSsoDescriptor.getNameIDFormats().stream().anyMatch(
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
        ProtocolSocketFactory socketFactory = null;
        SamlServiceProviderDefinition def = provider.getConfig().clone();
        if (def.getMetaDataLocation().startsWith("https")) {
            try {
                socketFactory = new EasySSLProtocolSocketFactory();
            } catch (GeneralSecurityException | IOException e) {
                throw new MetadataProviderException("Error instantiating SSL/TLS socket factory.", e);
            }
        } else {
            socketFactory = new DefaultProtocolSocketFactory();
        }
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setAlias(provider.getEntityId());
        FixedHttpMetaDataProvider fixedHttpMetaDataProvider;
        try {
            fixedHttpMetaDataProvider = FixedHttpMetaDataProvider.buildProvider(
                dummyTimer, getClientParams(),
                adjustURIForPort(def.getMetaDataLocation()),
                new RestTemplate(UaaHttpRequestUtils.createRequestFactory(def.isSkipSslValidation())),
                this.contentCache

            );
        } catch (URISyntaxException e) {
            throw new MetadataProviderException("Invalid metadata URI: " + def.getMetaDataLocation(), e);
        }
        fixedHttpMetaDataProvider.setSocketFactory(socketFactory);
        byte[] metadata = fixedHttpMetaDataProvider.fetchMetadata();
        def.setMetaDataLocation(new String(metadata, StandardCharsets.UTF_8));
        return configureXMLMetadata(provider);
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

    public SamlServiceProviderProvisioning getProviderProvisioning() { return providerProvisioning; }

    public void setProviderProvisioning(SamlServiceProviderProvisioning providerProvisioning) { this.providerProvisioning = providerProvisioning; }

    public HttpClientParams getClientParams() {
        return clientParams;
    }

    public void setClientParams(HttpClientParams clientParams) {
        this.clientParams = clientParams;
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
}
