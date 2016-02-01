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
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Objects;

public class SamlServiceProviderDefinition {

    public static final String DEFAULT_HTTP_SOCKET_FACTORY = "org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory";
    public static final String DEFAULT_HTTPS_SOCKET_FACTORY = "org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory";

    public enum MetadataLocation {
        URL,
        DATA,
        UNKNOWN
    }

    private String metaDataLocation;
    private String spEntityId;
    private String zoneId;
    private String nameID;
    private int singleSignOnServiceIndex;
    private boolean metadataTrustCheck;
    private String socketFactoryClassName;

    public SamlServiceProviderDefinition clone() {
        return new SamlServiceProviderDefinition(metaDataLocation,
                                                  spEntityId,
                                                  nameID,
                                                  singleSignOnServiceIndex,
                                                  metadataTrustCheck,
                                                  zoneId);
    }

    public SamlServiceProviderDefinition() {}

    public SamlServiceProviderDefinition(String metaDataLocation,
                                          String spEntityAlias,
                                          String nameID,
                                          int singleSignOnServiceIndex,
                                          boolean metadataTrustCheck,
                                          String zoneId) {
        this.metaDataLocation = metaDataLocation;
        this.spEntityId = spEntityAlias;
        this.nameID = nameID;
        this.singleSignOnServiceIndex = singleSignOnServiceIndex;
        this.metadataTrustCheck = metadataTrustCheck;
        this.zoneId = zoneId;
    }

    @JsonIgnore
    public MetadataLocation getType() {
        String trimmedLocation = metaDataLocation.trim();
        if (trimmedLocation.startsWith("<?xml") ||
            trimmedLocation.startsWith("<md:EntityDescriptor") ||
            trimmedLocation.startsWith("<EntityDescriptor")) {
            try {
                validateXml(trimmedLocation);
                return MetadataLocation.DATA;
            } catch (IllegalArgumentException x) {
                //invalid XML
            }
        } else if (trimmedLocation.startsWith("http")) {
            try {
                // This is here to validate the URL.
                @SuppressWarnings("unused")
                URL uri = new URL(trimmedLocation);
                return MetadataLocation.URL;
            } catch (MalformedURLException e) {
                //invalid URL
            }
        }
        return MetadataLocation.UNKNOWN;
    }

    protected void validateXml(String xml) throws IllegalArgumentException {
        if (xml==null || xml.toUpperCase().contains("<!DOCTYPE")) {
            throw new IllegalArgumentException("Invalid metadata XML contents:"+xml);
        }
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            builder.parse(new InputSource(new StringReader(xml)));
        } catch (ParserConfigurationException e) {
            throw new IllegalArgumentException("Unable to create document parser.", e);
        } catch (SAXException e) {
            throw new IllegalArgumentException("Sax Parsing exception of XML:"+xml, e);
        } catch (IOException e) {
            throw new IllegalArgumentException("IOException of XML:"+xml, e);
        }
    }

    public String getMetaDataLocation() {
        return metaDataLocation;
    }

    public void setMetaDataLocation(String metaDataLocation) {
        this.metaDataLocation = metaDataLocation;
    }

    public String getSpEntityId() {
        return spEntityId;
    }

    public void setSpEntityId(String spEntityId) {
        this.spEntityId = spEntityId;
    }

    public String getNameID() {
        return nameID;
    }

    public void setNameID(String nameID) {
        this.nameID = nameID;
    }

    public int getSingleSignOnServiceIndex() {
        return singleSignOnServiceIndex;
    }

    public void setSingleSignOnServiceIndex(int singleSignOnServiceIndex) {
        this.singleSignOnServiceIndex = singleSignOnServiceIndex;
    }

    public boolean isMetadataTrustCheck() {
        return metadataTrustCheck;
    }

    public void setMetadataTrustCheck(boolean metadataTrustCheck) {
        this.metadataTrustCheck = metadataTrustCheck;
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

    public String getZoneId() {
        return zoneId;
    }

    public void setZoneId(String zoneId) {
        this.zoneId = zoneId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SamlServiceProviderDefinition that = (SamlServiceProviderDefinition) o;

        return Objects.equals(getUniqueAlias(), that.getUniqueAlias());
    }

    @Override
    public int hashCode() {
        String alias = getUniqueAlias();
        return alias==null ? 0 : alias.hashCode();
    }

    @JsonIgnore
    protected String getUniqueAlias() {
        return getSpEntityId()+"###"+getZoneId();
    }

    @Override
    public String toString() {
        return "SamlServiceProviderDefinition{" +
            "spEntityAlias='" + spEntityId + '\'' +
            ", metaDataLocation='" + metaDataLocation + '\'' +
            ", nameID='" + nameID + '\'' +
            ", singleSignOnServiceIndex=" + singleSignOnServiceIndex +
            ", metadataTrustCheck=" + metadataTrustCheck +
            ", socketFactoryClassName='" + socketFactoryClassName + '\'' +
            ", zoneId='" + zoneId + '\'' +
            '}';
    }

    public static class Builder {

        private String metaDataLocation;
        private String spEntityId;
        private String zoneId;
        private String nameID;
        private int singleSignOnServiceIndex;
        private boolean metadataTrustCheck;
        private String socketFactoryClassName;

        private Builder(){}

        public static Builder get() {
            return new Builder();
        }

        public SamlServiceProviderDefinition build() {
            SamlServiceProviderDefinition def = new SamlServiceProviderDefinition();

            def.setMetaDataLocation(metaDataLocation);
            def.setSpEntityId(spEntityId);
            def.setZoneId(zoneId);
            def.setNameID(nameID);
            def.setSingleSignOnServiceIndex(singleSignOnServiceIndex);
            def.setMetadataTrustCheck(metadataTrustCheck);
            def.setSocketFactoryClassName(socketFactoryClassName);
            return def;
        }

        public Builder setMetaDataLocation(String metaDataLocation) {
            this.metaDataLocation = metaDataLocation;
            return this;
        }

        public Builder setSpEntityId(String spEntityId) {
            this.spEntityId = spEntityId;
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

        public Builder setSingleSignOnServiceIndex(int singleSignOnServiceIndex) {
            this.singleSignOnServiceIndex = singleSignOnServiceIndex;
            return this;
        }

        public Builder setMetadataTrustCheck(boolean metadataTrustCheck) {
            this.metadataTrustCheck = metadataTrustCheck;
            return this;
        }

        public Builder setSocketFactoryClassName(String socketFactoryClassName) {
            this.socketFactoryClassName = socketFactoryClassName;
            return this;
        }
    }
}
