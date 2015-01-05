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

import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.cloudfoundry.identity.uaa.login.util.FileLocator;

import java.io.File;
import java.io.IOException;

public class IdentityProviderDefinition {

    public static enum MetadataLocation {
        URL,
        FILE,
        DATA,
        UNKNOWN
    };

    private String metaDataLocation;
    private String idpEntityAlias;
    private String nameID;
    private int assertionConsumerIndex;
    private boolean metadataTrustCheck;
    private boolean showSamlLink;
    private String socketFactoryClassName;
    private String linkText;
    private String iconUrl;

    public MetadataLocation getType() {
        if (metaDataLocation.startsWith("<?xml")) {
            return MetadataLocation.DATA;
        } else if (metaDataLocation.startsWith("http")) {
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
        if (idpEntityAlias==null) {
            throw new NullPointerException("Alias can not be null");
        }

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
            return "org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory";
        } else {
            return "org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory";
        }
    }

    public void setSocketFactoryClassName(String socketFactoryClassName) {
        this.socketFactoryClassName = socketFactoryClassName;
        if (socketFactoryClassName!=null && socketFactoryClassName.trim().length()>0) {
            try {
                ProtocolSocketFactory test = (ProtocolSocketFactory)Class.forName(
                    socketFactoryClassName,
                    true,
                    Thread.currentThread().getContextClassLoader()
                ).newInstance();
            } catch (InstantiationException e) {
                throw new IllegalArgumentException(e);
            } catch (IllegalAccessException e) {
                throw new IllegalArgumentException(e);
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

}
