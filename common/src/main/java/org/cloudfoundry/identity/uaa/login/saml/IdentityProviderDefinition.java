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

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.cloudfoundry.identity.uaa.login.util.FileLocator;

import java.io.File;
import java.io.IOException;

public class IdentityProviderDefinition {

    public static final String DEFAULT_HTTP_SOCKET_FACTORY = "org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory";
    public static final String DEFAULT_HTTPS_SOCKET_FACTORY = "org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory";

    public static enum MetadataLocation {
        URL,
        FILE,
        DATA,
        UNKNOWN
    };

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

    public IdentityProviderDefinition() {}

    public IdentityProviderDefinition(String metaDataLocation, String idpEntityAlias, String nameID, int assertionConsumerIndex, boolean metadataTrustCheck, boolean showSamlLink, String linkText, String iconUrl, String zoneId) {
        this.metaDataLocation = metaDataLocation;
        this.idpEntityAlias = idpEntityAlias;
        this.nameID = nameID;
        this.assertionConsumerIndex = assertionConsumerIndex;
        this.metadataTrustCheck = metadataTrustCheck;
        this.showSamlLink = showSamlLink;
        this.linkText = linkText;
        this.iconUrl = iconUrl;
        this.zoneId = zoneId;
    }

    @JsonIgnore
    public MetadataLocation getType() {
        String trimmedLocation = metaDataLocation.trim();
        if (trimmedLocation.startsWith("<?xml") ||
            trimmedLocation.startsWith("<md:EntityDescriptor") ||
            trimmedLocation.startsWith("<EntityDescriptor")) {
            return MetadataLocation.DATA;
        } else if (trimmedLocation.startsWith("http")) {
            return MetadataLocation.URL;
        } else {
            try {
                File f = FileLocator.locate(metaDataLocation);
                if (f.exists() && f.canRead()) {
                    return MetadataLocation.FILE;
                }
            } catch (IOException x) {
                //file not found
            }
            return MetadataLocation.UNKNOWN;
        }
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
        return linkText;
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

    public IdentityProviderDefinition clone() {
        return new IdentityProviderDefinition(metaDataLocation, idpEntityAlias, nameID, assertionConsumerIndex, metadataTrustCheck, showSamlLink, linkText, iconUrl, zoneId);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        IdentityProviderDefinition that = (IdentityProviderDefinition) o;

        if (!idpEntityAlias.equals(that.idpEntityAlias)) return false;
        if (!zoneId.equals(that.zoneId)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = idpEntityAlias.hashCode();
        result = 31 * result + zoneId.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "IdentityProviderDefinition{" +
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
            '}';
    }
}
