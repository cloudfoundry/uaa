/*******************************************************************************
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
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class SamlServiceProviderDefinition {

    public enum MetadataLocation {
        URL,
        DATA,
        UNKNOWN
    }

    private String metaDataLocation;
    private String nameID;
    private int singleSignOnServiceIndex;
    private boolean metadataTrustCheck;
    private boolean skipSslValidation = false;
    private Map<String, Object> attributeMappings = new HashMap<>();
    private boolean enableIdpInitiatedSso = false;
    private Map<String, Object> staticCustomAttributes = new HashMap<>();


    public SamlServiceProviderDefinition clone() {
        return new SamlServiceProviderDefinition(metaDataLocation,
                                                 nameID,
                                                 singleSignOnServiceIndex,
                                                 metadataTrustCheck,
                                                 skipSslValidation,
                                                 attributeMappings,
                                                 enableIdpInitiatedSso);
    }

    public SamlServiceProviderDefinition() {}

    private SamlServiceProviderDefinition(String metaDataLocation,
                                         String nameID,
                                         int singleSignOnServiceIndex,
                                         boolean metadataTrustCheck,
                                         boolean skipSslValidation,
                                         Map<String, Object> attributeMappings,
                                         boolean enableIdpInitiatedSso) {
        this.metaDataLocation = metaDataLocation;
        this.nameID = nameID;
        this.singleSignOnServiceIndex = singleSignOnServiceIndex;
        this.metadataTrustCheck = metadataTrustCheck;
        this.skipSslValidation = skipSslValidation;
        this.attributeMappings = attributeMappings;
        this.enableIdpInitiatedSso = enableIdpInitiatedSso;
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
            factory.setExpandEntityReferences(false);
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

    @Override
    public int hashCode() {
        int result = metaDataLocation != null ? metaDataLocation.hashCode() : 0;
        result = 31 * result + (nameID != null ? nameID.hashCode() : 0);
        result = 31 * result + singleSignOnServiceIndex;
        result = 31 * result + (metadataTrustCheck ? 1 : 0);
        result = 31 * result + (skipSslValidation ? 1 : 0);
        result = 31 * result + (attributeMappings != null ? attributeMappings.hashCode() : 0);
        return result;
    }

    public boolean isSkipSslValidation() {
        return skipSslValidation;
    }

    public void setSkipSslValidation(boolean skipSslValidation) {
        this.skipSslValidation = skipSslValidation;
    }

    public void setAttributeMappings(Map<String, Object> attributeMappings) {
        this.attributeMappings = attributeMappings;
    }

    public Map<String, Object> getAttributeMappings() {
        return attributeMappings;
    }

    public boolean isEnableIdpInitiatedSso() {
        return enableIdpInitiatedSso;
    }

    public void setEnableIdpInitiatedSso(boolean enableIdpInitiatedSso) {
        this.enableIdpInitiatedSso = enableIdpInitiatedSso;
    }

    public Map<String, Object> getStaticCustomAttributes() {
        return staticCustomAttributes;
    }

    public void setStaticCustomAttributes(Map<String, Object> staticCustomAttributes) {
        this.staticCustomAttributes = staticCustomAttributes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        SamlServiceProviderDefinition that = (SamlServiceProviderDefinition) o;

        if (singleSignOnServiceIndex != that.singleSignOnServiceIndex) return false;
        if (metadataTrustCheck != that.metadataTrustCheck) return false;
        if (skipSslValidation != that.skipSslValidation) return false;
        if (!Objects.equals(metaDataLocation, that.metaDataLocation))
            return false;
        if (!Objects.equals(nameID, that.nameID)) return false;
        return Objects.equals(attributeMappings, that.attributeMappings);
    }

    @Override
    public String toString() {
        return "SamlServiceProviderDefinition{" +
            "metaDataLocation='" + metaDataLocation + '\'' +
            ", nameID='" + nameID + '\'' +
            ", singleSignOnServiceIndex=" + singleSignOnServiceIndex +
            ", metadataTrustCheck=" + metadataTrustCheck +
            ", skipSslValidation=" + skipSslValidation +
            ", attributeMappings=" + attributeMappings +
            '}';
    }

    public static class Builder {

        private String metaDataLocation;
        private String nameID;
        private int singleSignOnServiceIndex;
        private boolean metadataTrustCheck;
        private boolean enableIdpInitiatedSso = false;
        private boolean skipSslValidation = true;

        private Builder(){}

        public static Builder get() {
            return new Builder();
        }

        public SamlServiceProviderDefinition build() {
            SamlServiceProviderDefinition def = new SamlServiceProviderDefinition();
            def.setMetaDataLocation(metaDataLocation);
            def.setNameID(nameID);
            def.setSingleSignOnServiceIndex(singleSignOnServiceIndex);
            def.setMetadataTrustCheck(metadataTrustCheck);
            def.setEnableIdpInitiatedSso(enableIdpInitiatedSso);
            def.setSkipSslValidation(skipSslValidation);
            return def;
        }

        public Builder setMetaDataLocation(String metaDataLocation) {
            this.metaDataLocation = metaDataLocation;
            return this;
        }

        public Builder setNameID(String nameID) {
            this.nameID = nameID;
            return this;
        }

        public Builder setSkipSSLValidation(boolean skipSslValidation) {
            this.skipSslValidation = skipSslValidation;
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

        public Builder setEnableIdpInitiatedSso(boolean enableIdpInitiatedSso) {
            this.enableIdpInitiatedSso = enableIdpInitiatedSso;
            return this;
        }
    }
}
