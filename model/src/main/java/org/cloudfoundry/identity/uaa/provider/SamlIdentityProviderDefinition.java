/*
 * *****************************************************************************
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
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
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

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
@NoArgsConstructor
public class SamlIdentityProviderDefinition extends ExternalIdentityProviderDefinition {

    private String metaDataLocation;
    private String idpEntityAlias;
    private String zoneId;
    private String nameID;
    private int assertionConsumerIndex;
    private boolean metadataTrustCheck;
    private boolean showSamlLink;
    private String linkText;
    private String iconUrl;
    private ExternalGroupMappingMode groupMappingMode = ExternalGroupMappingMode.EXPLICITLY_MAPPED;
    private boolean skipSslValidation;
    private List<String> authnContext;

    @JsonIgnore
    private String idpEntityId;

    public SamlIdentityProviderDefinition clone() {
        List<String> emailDomain = getEmailDomain() != null ? new ArrayList<>(getEmailDomain()) : null;
        List<String> externalGroupsWhitelist = getExternalGroupsWhitelist() != null ? new ArrayList<>(getExternalGroupsWhitelist()) : null;
        List<String> authnContext = getAuthnContext() != null ? new ArrayList<>(getAuthnContext()) : null;
        Map<String, Object> attributeMappings = getAttributeMappings() != null ? new HashMap<>(getAttributeMappings()) : null;
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setMetaDataLocation(metaDataLocation);
        def.setIdpEntityAlias(idpEntityAlias);
        def.setIdpEntityId(idpEntityId);
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
        def.setSocketFactoryClassName(getSocketFactoryClassName());
        def.setSkipSslValidation(isSkipSslValidation());
        def.setStoreCustomAttributes(isStoreCustomAttributes());
        def.setAuthnContext(authnContext);
        return def;
    }

    @JsonIgnore
    public MetadataLocation getType() {
        return getType(this.metaDataLocation);
    }

    public static MetadataLocation getType(String urlOrXmlData) {
        String trimmedValue = urlOrXmlData.trim();

        if (trimmedValue.startsWith("<?xml") ||
                trimmedValue.startsWith("<md:EntityDescriptor") ||
                trimmedValue.startsWith("<EntityDescriptor")) {
            if (validateXml(trimmedValue)) {
                return MetadataLocation.DATA;
            }
        } else if (trimmedValue.startsWith("http")) {
            try {
                // Check if it is a valid URL
                new URL(trimmedValue);
                return MetadataLocation.URL;
            } catch (MalformedURLException e) {
                //invalid URL
            }
        }
        return MetadataLocation.UNKNOWN;
    }

    @JsonIgnore
    public String getIdpEntityId() {
        return this.idpEntityId;
    }

    @JsonIgnore
    public void setIdpEntityId(final String idpEntityId) {
        this.idpEntityId = idpEntityId;
    }

    private static boolean validateXml(String xml) {
        if (xml == null || xml.toUpperCase().contains("<!DOCTYPE")) {
            return false;
        }
        try {
            DocumentBuilder builder = ObjectUtils.getDocumentBuilder();
            builder.parse(new InputSource(new StringReader(xml)));
        } catch (ParserConfigurationException | SAXException | IOException e) {
            return false;
        }

        return true;
    }

    public SamlIdentityProviderDefinition setMetaDataLocation(String metaDataLocation) {
        this.metaDataLocation = metaDataLocation;
        return this;
    }

    public SamlIdentityProviderDefinition setIdpEntityAlias(String idpEntityAlias) {
        this.idpEntityAlias = idpEntityAlias;
        return this;
    }

    public SamlIdentityProviderDefinition setNameID(String nameID) {
        this.nameID = nameID;
        return this;
    }

    public SamlIdentityProviderDefinition setAuthnContext(List<String> authnContext) {
        this.authnContext = authnContext;
        return this;
    }

    public SamlIdentityProviderDefinition setAssertionConsumerIndex(int assertionConsumerIndex) {
        this.assertionConsumerIndex = assertionConsumerIndex;
        return this;
    }

    public SamlIdentityProviderDefinition setMetadataTrustCheck(boolean metadataTrustCheck) {
        this.metadataTrustCheck = metadataTrustCheck;
        return this;
    }

    public SamlIdentityProviderDefinition setShowSamlLink(boolean showSamlLink) {
        this.showSamlLink = showSamlLink;
        return this;
    }

    public String getSocketFactoryClassName() {
        return null;
    }

    public SamlIdentityProviderDefinition setSocketFactoryClassName(String socketFactoryClassName) {
        //no op
        return this;
    }

    public String getLinkText() {
        return StringUtils.hasText(linkText) ? linkText : idpEntityAlias;
    }

    public SamlIdentityProviderDefinition setLinkText(String linkText) {
        this.linkText = linkText;
        return this;
    }

    public SamlIdentityProviderDefinition setIconUrl(String iconUrl) {
        this.iconUrl = iconUrl;
        return this;
    }

    public SamlIdentityProviderDefinition setZoneId(String zoneId) {
        this.zoneId = zoneId;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        if (!super.equals(o)) {
            return false;
        }

        SamlIdentityProviderDefinition that = (SamlIdentityProviderDefinition) o;

        return Objects.equals(getUniqueAlias(), that.getUniqueAlias());
    }

    @Override
    public int hashCode() {
        String alias = getUniqueAlias();
        return alias == null ? 0 : alias.hashCode();
    }

    @JsonIgnore
    public String getUniqueAlias() {
        return getIdpEntityAlias() + "###" + getZoneId();
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
                ", socketFactoryClassName='deprected-not used'" +
                ", skipSslValidation=" + skipSslValidation +
                ", linkText='" + linkText + '\'' +
                ", iconUrl='" + iconUrl + '\'' +
                ", zoneId='" + zoneId + '\'' +
                ", addShadowUserOnLogin='" + isAddShadowUserOnLogin() + '\'' +
                '}';
    }

    public enum MetadataLocation {
        URL,
        DATA,
        UNKNOWN
    }

    public enum ExternalGroupMappingMode {
        EXPLICITLY_MAPPED,
        AS_SCOPES
    }
}
