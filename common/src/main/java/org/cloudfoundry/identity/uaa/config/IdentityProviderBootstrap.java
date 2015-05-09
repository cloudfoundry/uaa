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
package org.cloudfoundry.identity.uaa.config;


import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.dao.EmptyResultDataAccessException;

public class IdentityProviderBootstrap implements InitializingBean {
    public static final String DEFAULT_MAP = "{\"default\":\"default\"}";
    private IdentityProviderProvisioning provisioning;
    private List<IdentityProvider> providers = new LinkedList<>();
    private IdentityProviderConfigurator configurator;
    private HashMap<String, Object> ldapConfig;
    private HashMap<String, Object> keystoneConfig;
    private Environment environment;

    public IdentityProviderBootstrap(IdentityProviderProvisioning provisioning, Environment environment) {
        if (provisioning==null) {
            throw new NullPointerException("Constructor argument can't be null.");
        }
        this.provisioning = provisioning;
        this.environment = environment;
    }

    public void setSamlProviders(IdentityProviderConfigurator configurator) {
        this.configurator = configurator;
    }
    protected void addSamlProviders() {
        if (configurator==null) {
            return;
        }
        for (IdentityProviderDefinition def : configurator.getIdentityProviderDefinitions()) {
            IdentityProvider provider = new IdentityProvider();
            provider.setType(Origin.SAML);
            provider.setOriginKey(def.getIdpEntityAlias());
            provider.setName("UAA SAML Identity Provider["+provider.getOriginKey()+"]");
            try {
                provider.setConfig(JsonUtils.writeValueAsString(def));
            } catch (JsonUtils.JsonUtilException x) {
                throw new RuntimeException("Non serializable LDAP config");
            }
            providers.add(provider);
        }
    }

    public void setLdapConfig(HashMap<String, Object> ldapConfig) {
        this.ldapConfig = ldapConfig;
    }

    protected void addLdapProvider() {
        boolean ldapProfile = Arrays.asList(environment.getActiveProfiles()).contains(Origin.LDAP);
        if (ldapConfig != null || ldapProfile) {
            IdentityProvider provider = new IdentityProvider();
            provider.setOriginKey(Origin.LDAP);
            provider.setType(Origin.LDAP);
            provider.setName("UAA LDAP Provider");
            String json = ldapConfig != null ? JsonUtils.writeValueAsString(ldapConfig) : DEFAULT_MAP;
            provider.setConfig(json);
            providers.add(provider);
        }
    }

    public void setKeystoneConfig(HashMap<String, Object> keystoneConfig) {
        this.keystoneConfig = keystoneConfig;
    }

    protected void addKeystoneProvider() {
        boolean keystoneProfile = Arrays.asList(environment.getActiveProfiles()).contains(Origin.KEYSTONE);
        if (keystoneConfig != null || keystoneProfile) {
            IdentityProvider provider = new IdentityProvider();
            provider.setOriginKey(Origin.KEYSTONE);
            provider.setType(Origin.KEYSTONE);
            provider.setName("UAA LDAP Provider");
            String json = keystoneConfig != null ? JsonUtils.writeValueAsString(keystoneConfig) : DEFAULT_MAP;
            provider.setConfig(json);
            providers.add(provider);
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {

        providers.clear();
        addLdapProvider();
        addSamlProviders();
        addKeystoneProvider();

        String zoneId = IdentityZone.getUaa().getId();

        //deactivate all providers that are no longer present
        for (IdentityProvider provider: provisioning.retrieveAll(false, zoneId)) {
            if (Origin.SAML.equals(provider.getType()) ||
                Origin.LDAP.equals(provider.getType()) ||
                Origin.KEYSTONE.equals(provider.getType())) {
                if (!isAmongProviders(provider.getOriginKey())) {
                    provider.setActive(false);
                    provisioning.update(provider);
                }
            }
        }
        for (IdentityProvider provider: providers) {
            IdentityProvider existing = null;
            try {
                existing = provisioning.retrieveByOrigin(provider.getOriginKey(), zoneId);
            }catch (EmptyResultDataAccessException x){
            }
            provider.setIdentityZoneId(zoneId);
            provider.setActive(true);
            if (existing==null) {
                provisioning.create(provider);
            } else {
                provider.setId(existing.getId());
                provider.setCreated(existing.getCreated());
                provider.setVersion(existing.getVersion());
                provider.setLastModified(new Date(System.currentTimeMillis()));
                provisioning.update(provider);
            }
        }
    }

    public boolean isAmongProviders(String originKey) {
        for (IdentityProvider provider: providers) {
            if (provider.getOriginKey().equals(originKey)) {
                return true;
            }
        }
        return false;
    }
}
