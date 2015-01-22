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
package org.cloudfoundry.identity.uaa.login.saml;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.http.client.utils.URIBuilder;
import org.cloudfoundry.identity.uaa.login.ConfigMetadataProvider;
import org.cloudfoundry.identity.uaa.login.ssl.FixedHttpMetaDataProvider;
import org.cloudfoundry.identity.uaa.login.util.FileLocator;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Timer;

public class IdentityProviderConfigurator {


    private String legacyIdpIdentityAlias;
    private String legacyIdpMetaData;
    private String legacyNameId;
    private int legacyAssertionConsumerIndex;
    private boolean legacyMetadataTrustCheck = true;
    private boolean legacyShowSamlLink = true;
    private List<IdentityProviderDefinition> identityProviders = new LinkedList<>();
    private Timer metadataFetchingHttpClientTimer;
    private HttpClient httpClient;
    private BasicParserPool parserPool;

    public List<IdentityProviderDefinition> getIdentityProviderDefinitions() {
        List<IdentityProviderDefinition> providerDefinitions = new LinkedList<>(identityProviders);
        if (getLegacyIdpMetaData()!=null) {
            IdentityProviderDefinition def = new IdentityProviderDefinition();
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
            providerDefinitions.add(def);
        }
        Set<String> uniqueAlias = new HashSet<>();
        for (IdentityProviderDefinition def : providerDefinitions) {
            String alias = def.getIdpEntityAlias();
            if (uniqueAlias.contains(alias)) {
                throw new IllegalStateException("Duplicate IDP alias found:"+alias);
            }
            uniqueAlias.add(alias);
        }
        return providerDefinitions;
    }

    public List<ExtendedMetadataDelegate> getIdentityProviders() {

        List<ExtendedMetadataDelegate> result = new LinkedList<>();
        for (IdentityProviderDefinition def : getIdentityProviderDefinitions()) {
            switch (def.getType()) {
                case DATA: {
                    result.add(configureXMLMetadata(def));
                    break;
                }
                case FILE: {
                    result.add(configureFileMetadata(def));
                    break;
                }
                case URL: {
                    result.add(configureURLMetadata(def));
                    break;
                }
                default: {
                    throw new IllegalArgumentException("Invalid metadata type for alias["+def.getIdpEntityAlias()+"]:"+def.getMetaDataLocation());
                }
            }
        }
        return result;
    }

    protected ExtendedMetadataDelegate configureXMLMetadata(IdentityProviderDefinition def) {
        ConfigMetadataProvider configMetadataProvider = new ConfigMetadataProvider(def.getMetaDataLocation());
        configMetadataProvider.setParserPool(getParserPool());
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setLocal(false);
        extendedMetadata.setAlias(def.getIdpEntityAlias());
        ExtendedMetadataDelegate delegate = new ExtendedMetadataDelegate(configMetadataProvider, extendedMetadata);
        delegate.setMetadataTrustCheck(def.isMetadataTrustCheck());

        return delegate;
    }

    protected ExtendedMetadataDelegate configureFileMetadata(IdentityProviderDefinition def) {
        try {
            File metadataFile = FileLocator.locate(def.getMetaDataLocation());
            FilesystemMetadataProvider filesystemMetadataProvider = new FilesystemMetadataProvider(metadataFile);
            filesystemMetadataProvider.setParserPool(getParserPool());
            ExtendedMetadata extendedMetadata = new ExtendedMetadata();
            extendedMetadata.setAlias(def.getIdpEntityAlias());
            extendedMetadata.setLocal(false);
            ExtendedMetadataDelegate delegate = new ExtendedMetadataDelegate(filesystemMetadataProvider, extendedMetadata);
            delegate.setMetadataTrustCheck(def.isMetadataTrustCheck());
            return delegate;
        } catch (MetadataProviderException e) {
            throw new IllegalArgumentException("Invalid metadata for alias["+def.getIdpEntityAlias()+"]:"+def.getMetaDataLocation());
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid metadata file for alias["+def.getIdpEntityAlias()+"]:"+def.getMetaDataLocation());
        }

    }

    protected ExtendedMetadataDelegate configureURLMetadata(IdentityProviderDefinition def) {
        Class<ProtocolSocketFactory> socketFactory = null;
        try {
            socketFactory = (Class<ProtocolSocketFactory>) Class.forName(def.getSocketFactoryClassName());
            ExtendedMetadata extendedMetadata = new ExtendedMetadata();
            extendedMetadata.setAlias(def.getIdpEntityAlias());
            FixedHttpMetaDataProvider fixedHttpMetaDataProvider = new FixedHttpMetaDataProvider(getMetadataFetchingHttpClientTimer(), getHttpClient(), adjustURIForPort(def.getMetaDataLocation()));
            fixedHttpMetaDataProvider.setParserPool(getParserPool());
            fixedHttpMetaDataProvider.setSocketFactory(socketFactory.newInstance());
            ExtendedMetadataDelegate delegate = new ExtendedMetadataDelegate(fixedHttpMetaDataProvider, extendedMetadata);
            delegate.setMetadataTrustCheck(def.isMetadataTrustCheck());
            return delegate;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid socket factory(invalid URI):"+def.getMetaDataLocation(), e);
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("Invalid socket factory:"+def.getSocketFactoryClassName(), e);
        } catch (InstantiationException e) {
            throw new IllegalArgumentException("Invalid socket factory:"+def.getSocketFactoryClassName(), e);
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException("Invalid socket factory:"+def.getSocketFactoryClassName(), e);
        } catch (MetadataProviderException e) {
            throw new IllegalArgumentException("Invalid meta data", e);
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
            IdentityProviderDefinition def = new IdentityProviderDefinition();
            if (alias==null) {
                throw new IllegalArgumentException("Invalid IDP - alias must not be null ["+metaDataLocation+"]");
            }
            if (metaDataLocation==null) {
                throw new IllegalArgumentException("Invalid IDP - metaDataLocation must not be null ["+alias+"]");
            }
            def.setIdpEntityAlias(alias);
            def.setAssertionConsumerIndex(assertionIndex==null?0:assertionIndex);
            def.setMetaDataLocation(metaDataLocation);
            def.setNameID(nameID);
            def.setMetadataTrustCheck(trustCheck==null?true:trustCheck);
            def.setShowSamlLink(showLink==null?true:showLink);
            def.setSocketFactoryClassName(socketFactoryClassName);
            def.setLinkText(linkText);
            def.setIconUrl(iconUrl);
            identityProviders.add(def);
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

    public Timer getMetadataFetchingHttpClientTimer() {
        return metadataFetchingHttpClientTimer;
    }

    public void setMetadataFetchingHttpClientTimer(Timer metadataFetchingHttpClientTimer) {
        this.metadataFetchingHttpClientTimer = metadataFetchingHttpClientTimer;
    }

    public HttpClient getHttpClient() {
        return httpClient;
    }

    public void setHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
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
}
