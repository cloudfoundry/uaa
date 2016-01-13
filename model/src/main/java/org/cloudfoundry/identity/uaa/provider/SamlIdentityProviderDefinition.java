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
    private boolean addShadowUserOnLogin = true;

    public SamlIdentityProviderDefinition() {}

    public SamlIdentityProviderDefinition clone() {
        List<String> emailDomain = getEmailDomain() != null ? new ArrayList<>(getEmailDomain()) : null;
        List<String> externalGroupsWhitelist = getExternalGroupsWhitelist() != null ? new ArrayList<>(getExternalGroupsWhitelist()) : null;
        Map<String, Object> attributeMappings = getAttributeMappings() != null ? new HashMap(getAttributeMappings()) : null;
        return Builder.get()
            .setMetaDataLocation(metaDataLocation)
            .setIdpEntityAlias(idpEntityAlias)
            .setNameID(nameID)
            .setAssertionConsumerIndex(assertionConsumerIndex)
            .setMetadataTrustCheck(metadataTrustCheck)
            .setShowSamlLink(showSamlLink)
            .setLinkText(linkText)
            .setIconUrl(iconUrl)
            .setZoneId(zoneId)
            .setAddShadowUserOnLogin(addShadowUserOnLogin)
            .setEmailDomain(emailDomain)
            .setExternalGroupsWhitelist(externalGroupsWhitelist)
            .setAttributeMappings(attributeMappings)
            .build();
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

    public void setMetaDataLocation(String metaDataLocation) {
        this.metaDataLocation = metaDataLocation;
    }

    public String getIdpEntityAlias() {
        return idpEntityAlias;
    }

    public void setIdpEntityAlias(String idpEntityAlias) {
        this.idpEntityAlias = idpEntityAlias;
    }

    public String getNameID() {
        return nameID;
    }

    public void setNameID(String nameID) {
        this.nameID = nameID;
    }

    public int getAssertionConsumerIndex() {
        return assertionConsumerIndex;
    }

    public void setAssertionConsumerIndex(int assertionConsumerIndex) {
        this.assertionConsumerIndex = assertionConsumerIndex;
    }

    public boolean isMetadataTrustCheck() {
        return metadataTrustCheck;
    }

    public void setMetadataTrustCheck(boolean metadataTrustCheck) {
        this.metadataTrustCheck = metadataTrustCheck;
    }

    public boolean isShowSamlLink() {
        return showSamlLink;
    }

    public void setShowSamlLink(boolean showSamlLink) {
        this.showSamlLink = showSamlLink;
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

    public void setSocketFactoryClassName(String socketFactoryClassName) {
        this.socketFactoryClassName = socketFactoryClassName;
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
    }

    public String getLinkText() {
        return StringUtils.hasText(linkText) ? linkText : idpEntityAlias;
    }

    public void setLinkText(String linkText) {
        this.linkText = linkText;
    }

    public String getIconUrl() {
        return iconUrl;
    }

    public void setIconUrl(String iconUrl) {
        this.iconUrl = iconUrl;
    }

    public String getZoneId() {
        return zoneId;
    }

    public void setZoneId(String zoneId) {
        this.zoneId = zoneId;
    }

    public boolean isAddShadowUserOnLogin() {
        return addShadowUserOnLogin;
    }

    public void setAddShadowUserOnLogin(boolean addShadowUserOnLogin) {
        this.addShadowUserOnLogin = addShadowUserOnLogin;
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
            ", addShadowUserOnLogin='" + addShadowUserOnLogin + '\'' +
            '}';
    }

    public static class Builder {

        private String metaDataLocation;
        private String idpEntityAlias;
        private String zoneId;
        private String nameID;
        private int assertionConsumerIndex;
        private boolean metadataTrustCheck;
        private boolean showSamlLink;
        private String linkText;
        private String iconUrl;
        private boolean addShadowUserOnLogin = true;
        private List<String> emailDomain;
        private List<String> externalGroupsWhitelist;
        private Map<String, Object> attributeMappings;

        private Builder(){}

        public static Builder get() {
            return new Builder();
        }

        public SamlIdentityProviderDefinition build() {
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
            def.setAddShadowUserOnLogin(addShadowUserOnLogin);
            def.setEmailDomain(emailDomain);
            def.setExternalGroupsWhitelist(externalGroupsWhitelist);
            def.setAttributeMappings(attributeMappings);

            return def;
        }

        public Builder setAttributeMappings(Map<String, Object> attributeMappings) {
            this.attributeMappings = attributeMappings;
            return this;
        }

        public Builder setMetaDataLocation(String metaDataLocation) {
            this.metaDataLocation = metaDataLocation;
            return this;
        }

        public Builder setIdpEntityAlias(String idpEntityAlias) {
            this.idpEntityAlias = idpEntityAlias;
            return this;
        }

        public Builder setZoneId(String zoneId) {
            this.zoneId = zoneId;
            return this;
        }

        public Builder setNameID(String nameID) {
            this.nameID = nameID;
            return this;
        }

        public Builder setAssertionConsumerIndex(int assertionConsumerIndex) {
            this.assertionConsumerIndex = assertionConsumerIndex;
            return this;
        }

        public Builder setMetadataTrustCheck(boolean metadataTrustCheck) {
            this.metadataTrustCheck = metadataTrustCheck;
            return this;
        }

        public Builder setShowSamlLink(boolean showSamlLink) {
            this.showSamlLink = showSamlLink;
            return this;
        }

        public Builder setLinkText(String linkText) {
            this.linkText = linkText;
            return this;
        }

        public Builder setIconUrl(String iconUrl) {
            this.iconUrl = iconUrl;
            return this;
        }

        public Builder setAddShadowUserOnLogin(boolean addShadowUserOnLogin) {
            this.addShadowUserOnLogin = addShadowUserOnLogin;
            return this;
        }

        public Builder setEmailDomain(List<String> emailDomain) {
            this.emailDomain = emailDomain;
            return this;
        }

        public Builder setExternalGroupsWhitelist(List<String> externalGroupsWhitelist) {
            this.externalGroupsWhitelist = externalGroupsWhitelist;
            return this;
        }
    }
}
