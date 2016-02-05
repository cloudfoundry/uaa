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

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.SimpleHttpConnectionManager;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.utils.URIBuilder;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import static org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition.EMAIL_DOMAIN_ATTR;
import static org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition.PROVIDER_DESCRIPTION;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.ATTRIBUTE_MAPPINGS;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EXTERNAL_GROUPS_WHITELIST;
import static org.springframework.util.StringUtils.hasText;

public class SamlIdentityProviderConfigurator implements InitializingBean {
    private static Log logger = LogFactory.getLog(SamlIdentityProviderConfigurator.class);
    private String legacyIdpIdentityAlias;
    private volatile String legacyIdpMetaData;
    private String legacyNameId;
    private int legacyAssertionConsumerIndex;
    private boolean legacyMetadataTrustCheck = true;
    private boolean legacyShowSamlLink = true;
    private Map<SamlIdentityProviderDefinition, ExtendedMetadataDelegate> identityProviders = new HashMap<>();
    private List<SamlIdentityProviderDefinition> toBeFetchedProviders = new LinkedList<>();
    private HttpClientParams clientParams;
    private BasicParserPool parserPool;

    private Timer dummyTimer = new Timer() {
        @Override public void cancel() { super.cancel(); }
        @Override public int purge() {return 0; }
        @Override public void schedule(TimerTask task, long delay) {}
        @Override public void schedule(TimerTask task, long delay, long period) {}
        @Override public void schedule(TimerTask task, Date firstTime, long period) {}
        @Override public void schedule(TimerTask task, Date time) {}
        @Override public void scheduleAtFixedRate(TimerTask task, long delay, long period) {}
        @Override public void scheduleAtFixedRate(TimerTask task, Date firstTime, long period) {}
    };

    public SamlIdentityProviderConfigurator() {
        dummyTimer.cancel();
    }

    public List<SamlIdentityProviderDefinition> getIdentityProviderDefinitions() {
        return Collections.unmodifiableList(new ArrayList<>(identityProviders.keySet()));
    }

    public List<SamlIdentityProviderDefinition> getIdentityProviderDefinitionsForZone(IdentityZone zone) {
        List<SamlIdentityProviderDefinition> result = new LinkedList<>();
        for (SamlIdentityProviderDefinition def : getIdentityProviderDefinitions()) {
            if (zone.getId().equals(def.getZoneId())) {
                result.add(def);
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

    protected void parseIdentityProviderDefinitions() {
        identityProviders.clear();
        List<SamlIdentityProviderDefinition> providerDefinitions = new LinkedList<>(toBeFetchedProviders);
        if (getLegacyIdpMetaData()!=null) {
            SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
            def.setMetaDataLocation(getLegacyIdpMetaData());
            def.setMetadataTrustCheck(isLegacyMetadataTrustCheck());
            def.setNameID(getLegacyNameId());
            def.setAssertionConsumerIndex(getLegacyAssertionConsumerIndex());
            String alias = getLegacyIdpIdentityAlias();
            if (alias==null) {
                throw new IllegalArgumentException("Invalid IDP - Alias must be not null for deprecated IDP.");
            }
            def.setIdpEntityAlias(alias);
            def.setShowSamlLink(isLegacyShowSamlLink());
            def.setLinkText("Use your corporate credentials");
            def.setZoneId(IdentityZone.getUaa().getId()); //legacy only has UAA zone
            providerDefinitions.add(def);
        }
        Set<String> uniqueAlias = new HashSet<>();
        for (SamlIdentityProviderDefinition def : providerDefinitions) {
            String alias = getUniqueAlias(def);
            if (uniqueAlias.contains(alias)) {
                throw new IllegalStateException("Duplicate IDP alias found:"+alias);
            }
            uniqueAlias.add(alias);
        }
        for (SamlIdentityProviderDefinition def : providerDefinitions) {
            try {
                addSamlIdentityProviderDefinition(def);
            } catch (MetadataProviderException e) {
                logger.error("Unable to configure SAML provider:"+def, e);
            }
        }
    }

    protected String getUniqueAlias(SamlIdentityProviderDefinition def) {
        return def.getUniqueAlias();
    }

    /**
     * adds or replaces a SAML identity proviider
     * @param providerDefinition - the provider to be added
     * @return an array consisting of {provider-added, provider-deleted} where provider-deleted may be null
     * @throws MetadataProviderException if the system fails to fetch meta data for this provider
     */
    public synchronized ExtendedMetadataDelegate[] addSamlIdentityProviderDefinition(SamlIdentityProviderDefinition providerDefinition) throws MetadataProviderException {
        ExtendedMetadataDelegate added, deleted=null;
        if (providerDefinition==null) {
            throw new NullPointerException();
        }
        if (!hasText(providerDefinition.getIdpEntityAlias())) {
            throw new NullPointerException("SAML IDP Alias must be set");
        }
        if (!hasText(providerDefinition.getZoneId())) {
            throw new NullPointerException("IDP Zone Id must be set");
        }
        for (SamlIdentityProviderDefinition def : getIdentityProviderDefinitions()) {
            if (getUniqueAlias(providerDefinition).equals(getUniqueAlias(def))) {
                deleted = identityProviders.remove(def);
                break;
            }
        }
        SamlIdentityProviderDefinition clone = providerDefinition.clone();
        added = getExtendedMetadataDelegate(clone);
        String entityIDToBeAdded = ((ConfigMetadataProvider)added.getDelegate()).getEntityID();
        boolean entityIDexists = false;
        for (Map.Entry<SamlIdentityProviderDefinition, ExtendedMetadataDelegate> entry : identityProviders.entrySet()) {
            SamlIdentityProviderDefinition definition = entry.getKey();
            if (clone.getZoneId().equals(definition.getZoneId())) {
                ConfigMetadataProvider provider = (ConfigMetadataProvider) entry.getValue().getDelegate();
                if (entityIDToBeAdded.equals(provider.getEntityID())) {
                    entityIDexists = true;
                    break;
                }
            }
        }
        if (entityIDexists) {
            throw new MetadataProviderException("Duplicate entity ID:"+entityIDToBeAdded);
        }

        identityProviders.put(clone, added);
        return new ExtendedMetadataDelegate[] {added, deleted};
    }

    public synchronized ExtendedMetadataDelegate removeIdentityProviderDefinition(SamlIdentityProviderDefinition providerDefinition) {
        return identityProviders.remove(providerDefinition);
//        for (SamlIdentityProviderDefinition def : identityProviders.keySet()) {
//            if (getUniqueAlias(providerDefinition).equals(getUniqueAlias(def))) {
//                return identityProviders.remove(def);
//            }
//        }
//        return null;
    }

    public List<ExtendedMetadataDelegate> getSamlIdentityProviders() {
        return getSamlIdentityProviders(null);
    }

    public List<ExtendedMetadataDelegate> getSamlIdentityProviders(IdentityZone zone) {
        List<ExtendedMetadataDelegate> result = new LinkedList<>();
        for (SamlIdentityProviderDefinition def : getIdentityProviderDefinitions()) {
            if (zone==null || zone.getId().equals(def.getZoneId())) {
                ExtendedMetadataDelegate metadata = identityProviders.get(def);
                if (metadata!=null) {
                    result.add(metadata);
                }
            }
        }
        return result;
    }

    public ExtendedMetadataDelegate getExtendedMetadataDelegateFromCache(SamlIdentityProviderDefinition def) throws MetadataProviderException {
        return identityProviders.get(def);
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

    protected ExtendedMetadataDelegate configureURLMetadata(SamlIdentityProviderDefinition def) throws MetadataProviderException {
        Class<ProtocolSocketFactory> socketFactory = null;
        try {
            def = def.clone();
            socketFactory = (Class<ProtocolSocketFactory>) Class.forName(def.getSocketFactoryClassName());
            ExtendedMetadata extendedMetadata = new ExtendedMetadata();
            extendedMetadata.setAlias(def.getIdpEntityAlias());
            SimpleHttpConnectionManager connectionManager = new SimpleHttpConnectionManager(true);
            connectionManager.getParams().setDefaults(getClientParams());
            HttpClient client = new HttpClient(connectionManager);
            FixedHttpMetaDataProvider fixedHttpMetaDataProvider = new FixedHttpMetaDataProvider(dummyTimer, client, adjustURIForPort(def.getMetaDataLocation()));
            fixedHttpMetaDataProvider.setSocketFactory(socketFactory.newInstance());
            byte[] metadata = fixedHttpMetaDataProvider.fetchMetadata();
            def.setMetaDataLocation(new String(metadata, StandardCharsets.UTF_8));
            return configureXMLMetadata(def);
        } catch (URISyntaxException e) {
            throw new MetadataProviderException("Invalid socket factory(invalid URI):"+def.getMetaDataLocation(), e);
        } catch (ClassNotFoundException e) {
            throw new MetadataProviderException("Invalid socket factory:"+def.getSocketFactoryClassName(), e);
        } catch (InstantiationException e) {
            throw new MetadataProviderException("Invalid socket factory:"+def.getSocketFactoryClassName(), e);
        } catch (IllegalAccessException e) {
            throw new MetadataProviderException("Invalid socket factory:"+def.getSocketFactoryClassName(), e);
        }
    }

    protected String adjustURIForPort(String uri) throws URISyntaxException {
        URI metadataURI = new URI(uri);
        if (metadataURI.getPort()<0) {
            switch (metadataURI.getScheme()) {
                case "https" : return new URIBuilder(uri).setPort(443).build().toString();
                case "http"  : return new URIBuilder(uri).setPort(80).build().toString();
                default: return uri;
            }
        }
        return uri;
    }


    public void setIdentityProviders(Map<String, Map<String, Object>> providers) {
        identityProviders.clear();
        if (providers == null) {
            return;
        }
        for (Map.Entry entry : providers.entrySet()) {
            String alias = (String)entry.getKey();
            Map<String, Object> saml = (Map<String, Object>)entry.getValue();
            String metaDataLocation = (String)saml.get("idpMetadata");
            String nameID = (String)saml.get("nameID");
            Integer assertionIndex = (Integer)saml.get("assertionConsumerIndex");
            Boolean trustCheck = (Boolean)saml.get("metadataTrustCheck");
            Boolean showLink = (Boolean)((Map)entry.getValue()).get("showSamlLoginLink");
            String socketFactoryClassName = (String)saml.get("socketFactoryClassName");
            String linkText = (String)((Map)entry.getValue()).get("linkText");
            String iconUrl  = (String)((Map)entry.getValue()).get("iconUrl");
            String zoneId  = (String)((Map)entry.getValue()).get("zoneId");
            String providerDescription = (String)((Map)entry.getValue()).get(PROVIDER_DESCRIPTION);
            Boolean addShadowUserOnLogin = (Boolean)((Map)entry.getValue()).get("addShadowUserOnLogin");
            List<String> emailDomain = (List<String>) saml.get(EMAIL_DOMAIN_ATTR);
            List<String> externalGroupsWhitelist = (List<String>) saml.get(EXTERNAL_GROUPS_WHITELIST);
            Map<String, Object> attributeMappings = (Map<String, Object>) saml.get(ATTRIBUTE_MAPPINGS);
            SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
            if (hasText(providerDescription)) {
                def.setProviderDescription(providerDescription);
            }
            if (alias==null) {
                throw new IllegalArgumentException("Invalid IDP - alias must not be null ["+metaDataLocation+"]");
            }
            if (metaDataLocation==null) {
                throw new IllegalArgumentException("Invalid IDP - metaDataLocation must not be null ["+alias+"]");
            }
            def.setIdpEntityAlias(alias);
            def.setAssertionConsumerIndex(assertionIndex== null ? 0 :assertionIndex);
            def.setMetaDataLocation(metaDataLocation);
            def.setNameID(nameID);
            def.setMetadataTrustCheck(trustCheck==null?true:trustCheck);
            def.setShowSamlLink(showLink==null?true: showLink);
            def.setSocketFactoryClassName(socketFactoryClassName);
            def.setLinkText(linkText);
            def.setIconUrl(iconUrl);
            def.setEmailDomain(emailDomain);
            def.setExternalGroupsWhitelist(externalGroupsWhitelist);
            def.setAttributeMappings(attributeMappings);
            def.setZoneId(hasText(zoneId) ? zoneId : IdentityZone.getUaa().getId());
            def.setAddShadowUserOnLogin(addShadowUserOnLogin==null?true:addShadowUserOnLogin);
            toBeFetchedProviders.add(def);
        }
    }

    public String getLegacyIdpIdentityAlias() {
        return legacyIdpIdentityAlias;
    }

    public void setLegacyIdpIdentityAlias(String legacyIdpIdentityAlias) {
        if ("null".equals(legacyIdpIdentityAlias)) {
            this.legacyIdpIdentityAlias = null;
        } else {
            this.legacyIdpIdentityAlias = legacyIdpIdentityAlias;
        }
    }

    public String getLegacyIdpMetaData() {
        return legacyIdpMetaData;
    }

    public void setLegacyIdpMetaData(String legacyIdpMetaData) {
        if ("null".equals(legacyIdpMetaData)) {
            this.legacyIdpMetaData = null;
        } else {
            this.legacyIdpMetaData = legacyIdpMetaData;
        }
    }

    public String getLegacyNameId() {
        return legacyNameId;
    }

    public void setLegacyNameId(String legacyNameId) {
        this.legacyNameId = legacyNameId;
    }

    public int getLegacyAssertionConsumerIndex() {
        return legacyAssertionConsumerIndex;
    }

    public void setLegacyAssertionConsumerIndex(int legacyAssertionConsumerIndex) {
        this.legacyAssertionConsumerIndex = legacyAssertionConsumerIndex;
    }

    public boolean isLegacyMetadataTrustCheck() {
        return legacyMetadataTrustCheck;
    }

    public void setLegacyMetadataTrustCheck(boolean legacyMetadataTrustCheck) {
        this.legacyMetadataTrustCheck = legacyMetadataTrustCheck;
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

    public boolean isLegacyShowSamlLink() {
        return legacyShowSamlLink;
    }

    public void setLegacyShowSamlLink(boolean legacyShowSamlLink) {
        this.legacyShowSamlLink = legacyShowSamlLink;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        parseIdentityProviderDefinitions();
    }
}
