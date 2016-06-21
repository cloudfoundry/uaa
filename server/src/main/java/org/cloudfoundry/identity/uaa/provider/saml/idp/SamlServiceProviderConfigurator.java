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
import org.apache.http.client.utils.URIBuilder;
import org.cloudfoundry.identity.uaa.provider.saml.ConfigMetadataProvider;
import org.cloudfoundry.identity.uaa.provider.saml.FixedHttpMetaDataProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Holds internal state of available SAML Service Providers.
 */
public class SamlServiceProviderConfigurator {

    private final Map<IdentityZone, Map<String, SamlServiceProviderHolder>> zoneServiceProviders = new HashMap<>();
    private HttpClientParams clientParams;
    private BasicParserPool parserPool;

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

    public SamlServiceProviderConfigurator() {
        dummyTimer.cancel();
    }

    public List<SamlServiceProviderHolder> getSamlServiceProviders() {
        Map<String, SamlServiceProviderHolder> serviceProviders = getOrCreateSamlServiceProviderMapForZone(
                IdentityZoneHolder.get());
        return Collections.unmodifiableList(new ArrayList<>(serviceProviders.values()));
    }

    public List<SamlServiceProviderHolder> getSamlServiceProvidersForZone(IdentityZone zone) {
        Map<String, SamlServiceProviderHolder> serviceProviders = getOrCreateSamlServiceProviderMapForZone(zone);
        return Collections.unmodifiableList(new ArrayList<>(serviceProviders.values()));
    }

    public Map<String, SamlServiceProviderHolder> getSamlServiceProviderMapForZone(IdentityZone zone) {
        Map<String, SamlServiceProviderHolder> serviceProviders = getOrCreateSamlServiceProviderMapForZone(zone);
        return Collections.unmodifiableMap(serviceProviders);
    }

    private Map<String, SamlServiceProviderHolder> getOrCreateSamlServiceProviderMapForZone(IdentityZone zone) {
        Map<String, SamlServiceProviderHolder> serviceProviders = zoneServiceProviders.get(zone);
        if (serviceProviders == null) {
            synchronized (zoneServiceProviders) {
                serviceProviders = zoneServiceProviders.get(zone);
                if (serviceProviders == null) {
                    serviceProviders = new HashMap<>();
                    zoneServiceProviders.put(zone, serviceProviders);
                }
            }
        }
        return serviceProviders;
    }
    
    /**
     * adds or replaces a SAML service provider for the current zone.
     *
     * @param provider
     *            - the provider to be added
     * @return an array consisting of {provider-added, provider-deleted} where
     *         provider-deleted may be null
     * @throws MetadataProviderException
     *             if the system fails to fetch meta data for this provider
     */
    public ExtendedMetadataDelegate[] addSamlServiceProvider(SamlServiceProvider provider) throws MetadataProviderException {
        return addSamlServiceProvider(provider, IdentityZoneHolder.get());
    }

    synchronized ExtendedMetadataDelegate[] addSamlServiceProvider(SamlServiceProvider provider, IdentityZone zone)
            throws MetadataProviderException {

        if (provider == null) {
            throw new NullPointerException();
        }
        if (!StringUtils.hasText(provider.getEntityId())) {
            throw new NullPointerException("You must set the SAML SP Entity.");
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
        if (!provider.getEntityId().equals(metadataEntityId)) {
            throw new MetadataProviderException(
                    "Metadata entity id does not match SAML SP entity id: " + provider.getEntityId());
        }

        Map<String, SamlServiceProviderHolder> serviceProviders = getOrCreateSamlServiceProviderMapForZone(zone);

        ExtendedMetadataDelegate deleted = null;
        if (serviceProviders.containsKey(provider.getEntityId())) {
            deleted = serviceProviders.remove(provider.getEntityId()).getExtendedMetadataDelegate();
        }

        SamlServiceProviderHolder holder = new SamlServiceProviderHolder(added, provider);
        serviceProviders.put(provider.getEntityId(), holder);
        return new ExtendedMetadataDelegate[] { added, deleted };
    }

    public synchronized ExtendedMetadataDelegate removeSamlServiceProvider(String entityId) {
        Map<String, SamlServiceProviderHolder> serviceProviders = getOrCreateSamlServiceProviderMapForZone(
                IdentityZoneHolder.get());
        return serviceProviders.remove(entityId).getExtendedMetadataDelegate();
    }

    public ExtendedMetadataDelegate getExtendedMetadataDelegateFromCache(String entityId)
            throws MetadataProviderException {
        Map<String, SamlServiceProviderHolder> serviceProviders = getOrCreateSamlServiceProviderMapForZone(
                IdentityZoneHolder.get());
        return serviceProviders.get(entityId).getExtendedMetadataDelegate();
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
            fixedHttpMetaDataProvider = FixedHttpMetaDataProvider.buildProvider(dummyTimer, getClientParams(),
                    adjustURIForPort(def.getMetaDataLocation()));
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
}
