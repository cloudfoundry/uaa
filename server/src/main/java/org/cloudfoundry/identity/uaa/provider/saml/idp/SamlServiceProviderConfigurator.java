/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.SimpleHttpConnectionManager;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.http.client.utils.URIBuilder;
import org.cloudfoundry.identity.uaa.provider.saml.ConfigMetadataProvider;
import org.cloudfoundry.identity.uaa.provider.saml.FixedHttpMetaDataProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.util.StringUtils;

/**
 * Holds internal state of available SAML Service Providers.
 */
public class SamlServiceProviderConfigurator {
    private Map<SamlServiceProviderDefinition, ExtendedMetadataDelegate> serviceProviders = new HashMap<>();
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

    public List<SamlServiceProviderDefinition> getSamlServiceProviderDefinitions() {
        return Collections.unmodifiableList(new ArrayList<>(serviceProviders.keySet()));
    }

    public List<SamlServiceProviderDefinition> getSamlServiceProviderDefinitionsForZone(IdentityZone zone) {
        List<SamlServiceProviderDefinition> result = new LinkedList<>();
        for (SamlServiceProviderDefinition def : getSamlServiceProviderDefinitions()) {
            if (zone.getId().equals(def.getZoneId())) {
                result.add(def);
            }
        }
        return result;
    }

    public List<SamlServiceProviderDefinition> getSamlServiceProviderDefinitions(List<String> allowedSps,
            IdentityZone zone) {
        List<SamlServiceProviderDefinition> spsInTheZone = getSamlServiceProviderDefinitionsForZone(zone);
        if (allowedSps != null) {
            List<SamlServiceProviderDefinition> result = new LinkedList<>();
            for (SamlServiceProviderDefinition def : spsInTheZone) {
                if (allowedSps.contains(def.getSpEntityId())) {
                    result.add(def);
                }
            }
            return result;
        }
        return spsInTheZone;
    }

    protected String getUniqueAlias(SamlServiceProviderDefinition def) {
        return def.getUniqueAlias();
    }

    /**
     * adds or replaces a SAML service provider
     * 
     * @param providerDefinition
     *            - the provider to be added
     * @return an array consisting of {provider-added, provider-deleted} where provider-deleted may be null
     * @throws MetadataProviderException
     *             if the system fails to fetch meta data for this provider
     */
    public synchronized ExtendedMetadataDelegate[] addSamlServiceProviderDefinition(
            SamlServiceProviderDefinition providerDefinition) throws MetadataProviderException {
        ExtendedMetadataDelegate added, deleted = null;
        if (providerDefinition == null) {
            throw new NullPointerException();
        }
        if (!StringUtils.hasText(providerDefinition.getSpEntityId())) {
            throw new NullPointerException("You must set the SAML SP Entity.");
        }
        if (!StringUtils.hasText(providerDefinition.getZoneId())) {
            throw new NullPointerException("You must set the SAML SP Identity Zone Id.");
        }
        for (SamlServiceProviderDefinition def : getSamlServiceProviderDefinitions()) {
            if (getUniqueAlias(providerDefinition).equals(getUniqueAlias(def))) {
                deleted = serviceProviders.remove(def);
                break;
            }
        }
        SamlServiceProviderDefinition clone = providerDefinition.clone();
        added = getExtendedMetadataDelegate(clone);
        String entityIdToBeAdded = ((ConfigMetadataProvider) added.getDelegate()).getEntityID();
        boolean entityIDexists = false;
        for (Map.Entry<SamlServiceProviderDefinition, ExtendedMetadataDelegate> entry : serviceProviders.entrySet()) {
            SamlServiceProviderDefinition definition = entry.getKey();
            if (clone.getZoneId().equals(definition.getZoneId())) {
                ConfigMetadataProvider provider = (ConfigMetadataProvider) entry.getValue().getDelegate();
                if (entityIdToBeAdded.equals(provider.getEntityID())) {
                    entityIDexists = true;
                    break;
                }
            }
        }
        if (entityIDexists) {
            throw new MetadataProviderException("Duplicate entity id:" + entityIdToBeAdded);
        }

        serviceProviders.put(clone, added);
        return new ExtendedMetadataDelegate[] { added, deleted };
    }

    public synchronized ExtendedMetadataDelegate removeSamlServiceProviderDefinition(
            SamlServiceProviderDefinition providerDefinition) {
        return serviceProviders.remove(providerDefinition);
    }

    public List<ExtendedMetadataDelegate> getSamlServiceProviders() {
        return getSamlServiceProviders(null);
    }

    public List<ExtendedMetadataDelegate> getSamlServiceProviders(IdentityZone zone) {
        List<ExtendedMetadataDelegate> result = new LinkedList<>();
        for (SamlServiceProviderDefinition def : getSamlServiceProviderDefinitions()) {
            if (zone == null || zone.getId().equals(def.getZoneId())) {
                ExtendedMetadataDelegate metadata = serviceProviders.get(def);
                if (metadata != null) {
                    result.add(metadata);
                }
            }
        }
        return result;
    }

    public ExtendedMetadataDelegate getExtendedMetadataDelegateFromCache(SamlServiceProviderDefinition def)
            throws MetadataProviderException {
        return serviceProviders.get(def);
    }

    public ExtendedMetadataDelegate getExtendedMetadataDelegate(SamlServiceProviderDefinition def)
            throws MetadataProviderException {
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
            throw new MetadataProviderException(
                    "Invalid metadata type for alias[" + def.getSpEntityId() + "]:" + def.getMetaDataLocation());
        }
        }
        return metadata;
    }

    protected ExtendedMetadataDelegate configureXMLMetadata(SamlServiceProviderDefinition def) {
        ConfigMetadataProvider configMetadataProvider = new ConfigMetadataProvider(def.getZoneId(), def.getSpEntityId(),
                def.getMetaDataLocation());
        configMetadataProvider.setParserPool(getParserPool());
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setLocal(false);
        extendedMetadata.setAlias(def.getSpEntityId());
        ExtendedMetadataDelegate delegate = new ExtendedMetadataDelegate(configMetadataProvider, extendedMetadata);
        delegate.setMetadataTrustCheck(def.isMetadataTrustCheck());

        return delegate;
    }

    @SuppressWarnings("unchecked")
    protected ExtendedMetadataDelegate configureURLMetadata(SamlServiceProviderDefinition def)
            throws MetadataProviderException {
        Class<ProtocolSocketFactory> socketFactory = null;
        try {
            def = def.clone();
            socketFactory = (Class<ProtocolSocketFactory>) Class.forName(def.getSocketFactoryClassName());
            ExtendedMetadata extendedMetadata = new ExtendedMetadata();
            extendedMetadata.setAlias(def.getSpEntityId());
            SimpleHttpConnectionManager connectionManager = new SimpleHttpConnectionManager(true);
            connectionManager.getParams().setDefaults(getClientParams());
            HttpClient client = new HttpClient(connectionManager);
            FixedHttpMetaDataProvider fixedHttpMetaDataProvider = new FixedHttpMetaDataProvider(dummyTimer, client,
                    adjustURIForPort(def.getMetaDataLocation()));
            fixedHttpMetaDataProvider.setSocketFactory(socketFactory.newInstance());
            byte[] metadata = fixedHttpMetaDataProvider.fetchMetadata();
            def.setMetaDataLocation(new String(metadata, StandardCharsets.UTF_8));
            return configureXMLMetadata(def);
        } catch (URISyntaxException e) {
            throw new MetadataProviderException("Invalid socket factory(invalid URI):" + def.getMetaDataLocation(), e);
        } catch (ClassNotFoundException e) {
            throw new MetadataProviderException("Invalid socket factory:" + def.getSocketFactoryClassName(), e);
        } catch (InstantiationException e) {
            throw new MetadataProviderException("Invalid socket factory:" + def.getSocketFactoryClassName(), e);
        } catch (IllegalAccessException e) {
            throw new MetadataProviderException("Invalid socket factory:" + def.getSocketFactoryClassName(), e);
        }
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
