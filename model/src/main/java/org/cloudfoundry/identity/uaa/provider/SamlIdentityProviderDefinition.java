/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.springframework.util.StringUtils;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class SamlIdentityProviderDefinition extends ExternalIdentityProviderDefinition {

    public static final String DEFAULT_HTTP_SOCKET_FACTORY = "org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory";
    public static final String DEFAULT_HTTPS_SOCKET_FACTORY = "org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory";

    public enum MetadataLocation {
        URL,
        DATA,
        UNKNOWN
    }

    public enum ExternalGroupMappingMode {
        EXPLICITLY_MAPPED,
        AS_SCOPES
    }

    private String metaDataLocation;
    private String idpEntityAlias;
    private String zoneId;
    private String nameID;
    private int assertionConsumerIndex;
    private boolean metadataTrustCheck;
    private boolean showSamlLink;
    private String socketFactoryClassName;
    private String linkText;
    private String iconUrl;
    private ExternalGroupMappingMode groupMappingMode = ExternalGroupMappingMode.EXPLICITLY_MAPPED;

    public SamlIdentityProviderDefinition() {}

    public SamlIdentityProviderDefinition clone() {
        List<String> emailDomain = getEmailDomain() != null ? new ArrayList<>(getEmailDomain()) : null;
        List<String> externalGroupsWhitelist = getExternalGroupsWhitelist() != null ? new ArrayList<>(getExternalGroupsWhitelist()) : null;
        Map<String, Object> attributeMappings = getAttributeMappings() != null ? new HashMap(getAttributeMappings()) : null;
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setMetaDataLocation(metaDataLocation);
        def.setIdpEntityAlias(idpEntityAlias);
        def.setZoneId(zoneId);
        def.setNameID(nameID);
        def.setAssertionConsumerIndex(assertionConsumerIndex);
        def.setMetadataTrustCheck(metadataTrustCheck);
        def.setShowSamlLink(showSamlLink);
        def.setLinkText(linkText);
        def.setIconUrl(iconUrl);
        def.setAddShadowUserOnLogin(isAddShadowUserOnLogin());
        def.setEmailDomain(emailDomain);
        def.setExternalGroupsWhitelist(externalGroupsWhitelist);
        def.setAttributeMappings(attributeMappings);
        def.setAdditionalConfiguration(getAdditionalConfiguration());
        def.setProviderDescription(getProviderDescription());
        def.setGroupMappingMode(getGroupMappingMode());
        return def;
    }

    @JsonIgnore
    public MetadataLocation getType() {
        String trimmedLocation = metaDataLocation.trim();
        if (trimmedLocation.startsWith("<?xml") ||
            trimmedLocation.startsWith("<md:EntityDescriptor") ||
            trimmedLocation.startsWith("<EntityDescriptor")) {
            if(validateXml(trimmedLocation)) {
                return MetadataLocation.DATA;
            }
        } else if (trimmedLocation.startsWith("http")) {
            try {
                URL uri = new URL(trimmedLocation);
                return MetadataLocation.URL;
            } catch (MalformedURLException e) {
                //invalid URL
            }
        }
        return MetadataLocation.UNKNOWN;
    }

    private boolean validateXml(String xml) {
        if (xml==null || xml.toUpperCase().contains("<!DOCTYPE")) {
            return false;
        }
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setExpandEntityReferences(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.parse(new InputSource(new StringReader(xml)));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            return false;
        }

        return true;
    }

    public String getMetaDataLocation() {
        return metaDataLocation;
    }

    public SamlIdentityProviderDefinition setMetaDataLocation(String metaDataLocation) {
        this.metaDataLocation = metaDataLocation;
        return this;
    }

    public String getIdpEntityAlias() {
        return idpEntityAlias;
    }

    public SamlIdentityProviderDefinition setIdpEntityAlias(String idpEntityAlias) {
        this.idpEntityAlias = idpEntityAlias;
        return this;
    }

    public String getNameID() {
        return nameID;
    }

    public SamlIdentityProviderDefinition setNameID(String nameID) {
        this.nameID = nameID;
        return this;
    }

    public int getAssertionConsumerIndex() {
        return assertionConsumerIndex;
    }

    public SamlIdentityProviderDefinition setAssertionConsumerIndex(int assertionConsumerIndex) {
        this.assertionConsumerIndex = assertionConsumerIndex;
        return this;
    }

    public boolean isMetadataTrustCheck() {
        return metadataTrustCheck;
    }

    public SamlIdentityProviderDefinition setMetadataTrustCheck(boolean metadataTrustCheck) {
        this.metadataTrustCheck = metadataTrustCheck;
        return this;
    }

    public boolean isShowSamlLink() {
        return showSamlLink;
    }

    public SamlIdentityProviderDefinition setShowSamlLink(boolean showSamlLink) {
        this.showSamlLink = showSamlLink;
        return this;
    }

    public ExternalGroupMappingMode getGroupMappingMode() {
        return groupMappingMode;
    }

    public void setGroupMappingMode(ExternalGroupMappingMode asScopes) {
        this.groupMappingMode = asScopes;
    }

    public String getSocketFactoryClassName() {
        if (socketFactoryClassName!=null && socketFactoryClassName.trim().length()>0) {
            return socketFactoryClassName;
        }
        if (getMetaDataLocation()==null || getMetaDataLocation().trim().length()==0) {
            throw new IllegalStateException("Invalid meta data URL[" + getMetaDataLocation() + "] cannot determine socket factory.");
        }
        if (getMetaDataLocation().startsWith("https")) {
            return DEFAULT_HTTPS_SOCKET_FACTORY;
        } else {
            return DEFAULT_HTTP_SOCKET_FACTORY;
        }
    }

    public SamlIdentityProviderDefinition setSocketFactoryClassName(String socketFactoryClassName) {
        if (socketFactoryClassName!=null && socketFactoryClassName.trim().length()>0) {
            try {
                Class.forName(
                    socketFactoryClassName,
                    true,
                    Thread.currentThread().getContextClassLoader()
                );
            } catch (ClassNotFoundException e) {
                throw new IllegalArgumentException(e);
            } catch (ClassCastException e) {
                throw new IllegalArgumentException(e);
            }
        }
        this.socketFactoryClassName = socketFactoryClassName;
        return this;
    }

    public String getLinkText() {
        return StringUtils.hasText(linkText) ? linkText : idpEntityAlias;
    }

    public SamlIdentityProviderDefinition setLinkText(String linkText) {
        this.linkText = linkText;
        return this;
    }

    public String getIconUrl() {
        return iconUrl;
    }

    public SamlIdentityProviderDefinition setIconUrl(String iconUrl) {
        this.iconUrl = iconUrl;
        return this;
    }

    public String getZoneId() {
        return zoneId;
    }

    public SamlIdentityProviderDefinition setZoneId(String zoneId) {
        this.zoneId = zoneId;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SamlIdentityProviderDefinition that = (SamlIdentityProviderDefinition) o;

        return Objects.equals(getUniqueAlias(), that.getUniqueAlias());
    }

    @Override
    public int hashCode() {
        String alias = getUniqueAlias();
        return alias==null ? 0 : alias.hashCode();
    }

    @JsonIgnore
    public String getUniqueAlias() {
        return getIdpEntityAlias()+"###"+getZoneId();
    }

    @Override
    public String toString() {
        return "SamlIdentityProviderDefinition{" +
            "idpEntityAlias='" + idpEntityAlias + '\'' +
            ", metaDataLocation='" + metaDataLocation + '\'' +
            ", nameID='" + nameID + '\'' +
            ", assertionConsumerIndex=" + assertionConsumerIndex +
            ", metadataTrustCheck=" + metadataTrustCheck +
            ", showSamlLink=" + showSamlLink +
            ", socketFactoryClassName='" + socketFactoryClassName + '\'' +
            ", linkText='" + linkText + '\'' +
            ", iconUrl='" + iconUrl + '\'' +
            ", zoneId='" + zoneId + '\'' +
            ", addShadowUserOnLogin='" + isAddShadowUserOnLogin() + '\'' +
            '}';
    }

 }
