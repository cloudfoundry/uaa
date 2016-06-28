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

import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.fasterxml.jackson.annotation.JsonIgnore;

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

    public SamlServiceProviderDefinition clone() {
        return new SamlServiceProviderDefinition(metaDataLocation,
                                                  nameID,
                                                  singleSignOnServiceIndex,
                                                  metadataTrustCheck);
    }

    public SamlServiceProviderDefinition() {}

    public SamlServiceProviderDefinition(String metaDataLocation,
                                          String nameID,
                                          int singleSignOnServiceIndex,
                                          boolean metadataTrustCheck) {
        this.metaDataLocation = metaDataLocation;
        this.nameID = nameID;
        this.singleSignOnServiceIndex = singleSignOnServiceIndex;
        this.metadataTrustCheck = metadataTrustCheck;
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
        final int prime = 31;
        int result = 1;
        result = prime * result + ((metaDataLocation == null) ? 0 : metaDataLocation.hashCode());
        result = prime * result + (metadataTrustCheck ? 1231 : 1237);
        result = prime * result + ((nameID == null) ? 0 : nameID.hashCode());
        result = prime * result + singleSignOnServiceIndex;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        SamlServiceProviderDefinition other = (SamlServiceProviderDefinition) obj;
        if (metaDataLocation == null) {
            if (other.metaDataLocation != null)
                return false;
        } else if (!metaDataLocation.equals(other.metaDataLocation))
            return false;
        if (metadataTrustCheck != other.metadataTrustCheck)
            return false;
        if (nameID == null) {
            if (other.nameID != null)
                return false;
        } else if (!nameID.equals(other.nameID))
            return false;
        if (singleSignOnServiceIndex != other.singleSignOnServiceIndex)
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "SamlServiceProviderDefinition{" +
            ", metaDataLocation='" + metaDataLocation + '\'' +
            ", nameID='" + nameID + '\'' +
            ", singleSignOnServiceIndex=" + singleSignOnServiceIndex +
            ", metadataTrustCheck=" + metadataTrustCheck +
            '}';
    }

    public static class Builder {

        private String metaDataLocation;
        private String nameID;
        private int singleSignOnServiceIndex;
        private boolean metadataTrustCheck;

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

        public Builder setSingleSignOnServiceIndex(int singleSignOnServiceIndex) {
            this.singleSignOnServiceIndex = singleSignOnServiceIndex;
            return this;
        }

        public Builder setMetadataTrustCheck(boolean metadataTrustCheck) {
            this.metadataTrustCheck = metadataTrustCheck;
            return this;
        }
    }
}
