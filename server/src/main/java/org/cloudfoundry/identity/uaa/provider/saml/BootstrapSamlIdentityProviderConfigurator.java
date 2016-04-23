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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition.ExternalGroupMappingMode;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.beans.factory.InitializingBean;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
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

public class BootstrapSamlIdentityProviderConfigurator implements InitializingBean {
    private static Log logger = LogFactory.getLog(BootstrapSamlIdentityProviderConfigurator.class);
    private String legacyIdpIdentityAlias;
    private volatile String legacyIdpMetaData;
    private String legacyNameId;
    private int legacyAssertionConsumerIndex;
    private boolean legacyMetadataTrustCheck = true;
    private boolean legacyShowSamlLink = true;
    private List<SamlIdentityProviderDefinition> identityProviders = new LinkedList<>();
    private List<SamlIdentityProviderDefinition> toBeFetchedProviders = new LinkedList<>();

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

    public BootstrapSamlIdentityProviderConfigurator() {
        dummyTimer.cancel();
    }

    public List<SamlIdentityProviderDefinition> getIdentityProviderDefinitions() {
        return Collections.unmodifiableList(new ArrayList<>(identityProviders));
    }

    protected void parseIdentityProviderDefinitions() {
        identityProviders.clear();
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
            identityProviders.add(def);
        }
        Set<String> uniqueAlias = new HashSet<>();
        for (SamlIdentityProviderDefinition def : toBeFetchedProviders) {
            String alias = getUniqueAlias(def);
            if (uniqueAlias.contains(alias)) {
                throw new IllegalStateException("Duplicate IDP alias found:"+alias);
            }
            uniqueAlias.add(alias);
            identityProviders.add(def);
        }
    }

    protected String getUniqueAlias(SamlIdentityProviderDefinition def) {
        return def.getUniqueAlias();
    }

    public void setIdentityProviders(Map<String, Map<String, Object>> providers) {
        identityProviders.clear();
        toBeFetchedProviders.clear();
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
            String groupMappingMode = (String)((Map)entry.getValue()).get("groupMappingMode");
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
            if(hasText(groupMappingMode)) { def.setGroupMappingMode(ExternalGroupMappingMode.valueOf(groupMappingMode)); }
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
