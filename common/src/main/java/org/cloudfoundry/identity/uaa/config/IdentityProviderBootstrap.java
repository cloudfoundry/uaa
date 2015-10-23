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


import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaMapUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.json.JSONException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.dao.EmptyResultDataAccessException;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition.LDAP;
import static org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition.LDAP_PROPERTY_NAMES;
import static org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition.LDAP_PROPERTY_TYPES;

public class IdentityProviderBootstrap implements InitializingBean {
    public static final String DEFAULT_MAP = "{\"default\":\"default\"}";
    private IdentityProviderProvisioning provisioning;
    private List<IdentityProvider> providers = new LinkedList<>();
    private SamlIdentityProviderConfigurator configurator;
    private HashMap<String, Object> ldapConfig;
    private HashMap<String, Object> keystoneConfig;
    private Environment environment;
    private PasswordPolicy defaultPasswordPolicy;
    private LockoutPolicy defaultLockoutPolicy;
    private boolean disableInternalUserManagement;

    public IdentityProviderBootstrap(IdentityProviderProvisioning provisioning, Environment environment) {
        if (provisioning==null) {
            throw new NullPointerException("Constructor argument can't be null.");
        }
        this.provisioning = provisioning;
        this.environment = environment;

    }

    public void setSamlProviders(SamlIdentityProviderConfigurator configurator) {
        this.configurator = configurator;
    }
    protected void addSamlProviders() {
        if (configurator==null) {
            return;
        }
        for (SamlIdentityProviderDefinition def : configurator.getIdentityProviderDefinitions()) {
            IdentityProvider provider = new IdentityProvider();
            provider.setType(Origin.SAML);
            provider.setOriginKey(def.getIdpEntityAlias());
            provider.setName("UAA SAML Identity Provider["+provider.getOriginKey()+"]");
            provider.setActive(true);
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
            boolean active = ldapProfile && ldapConfig!=null;
            IdentityProvider provider = new IdentityProvider();
            provider.setActive(ldapProfile);
            provider.setOriginKey(Origin.LDAP);
            provider.setType(Origin.LDAP);
            provider.setName("UAA LDAP Provider");
            provider.setActive(active);
            Map<String,Object> ldap = new HashMap<>();
            ldap.put(LDAP, ldapConfig);
            String json = getLdapConfigAsDefinition(ldap);
            provider.setConfig(json);
            providers.add(provider);
        }
    }



    protected String getLdapConfigAsDefinition(Map<String, Object> ldapConfig) {
        ldapConfig = UaaMapUtils.flatten(ldapConfig);
        populateLdapEnvironment(ldapConfig);
        if (ldapConfig.isEmpty()) {
            return JsonUtils.writeValueAsString(new LdapIdentityProviderDefinition());
        }
        return JsonUtils.writeValueAsString(LdapIdentityProviderDefinition.fromConfig(ldapConfig));
    }

    protected void populateLdapEnvironment(Map<String, Object> ldapConfig) {
        //this method reads the environment and overwrites values (needed by LdapMockMvcTests that overrides properties through env)
        AbstractEnvironment env = (AbstractEnvironment)environment;
        for (String property : LDAP_PROPERTY_NAMES) {
            if (env.containsProperty(property) && LDAP_PROPERTY_TYPES.get(property)!=null) {
                ldapConfig.put(property, env.getProperty(property, LDAP_PROPERTY_TYPES.get(property)));
            }
        }
    }

    public void setKeystoneConfig(HashMap<String, Object> keystoneConfig) {
        this.keystoneConfig = keystoneConfig;
    }

    protected void addKeystoneProvider() {
        boolean keystoneProfile = Arrays.asList(environment.getActiveProfiles()).contains(Origin.KEYSTONE);
        if (keystoneConfig != null || keystoneProfile) {
            boolean active = keystoneProfile && keystoneConfig!=null;
            IdentityProvider provider = new IdentityProvider();
            provider.setOriginKey(Origin.KEYSTONE);
            provider.setType(Origin.KEYSTONE);
            provider.setName("UAA LDAP Provider");
            provider.setActive(active);
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
        deactivateUnusedProviders(zoneId);

        for (IdentityProvider provider: providers) {
            IdentityProvider existing = null;
            try {
                existing = provisioning.retrieveByOrigin(provider.getOriginKey(), zoneId);
            }catch (EmptyResultDataAccessException x){
            }
            provider.setIdentityZoneId(zoneId);
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
        updateDefaultZoneUaaIDP();
    }

    private void deactivateUnusedProviders(String zoneId) {
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
    }

    protected void updateDefaultZoneUaaIDP() throws JSONException {
        IdentityProvider internalIDP = provisioning.retrieveByOrigin(Origin.UAA, IdentityZone.getUaa().getId());
        UaaIdentityProviderDefinition identityProviderDefinition = new UaaIdentityProviderDefinition(defaultPasswordPolicy, defaultLockoutPolicy, disableInternalUserManagement);
        internalIDP.setConfig(JsonUtils.writeValueAsString(identityProviderDefinition));
        String disableInternalAuth = environment.getProperty("disableInternalAuth");
        if (disableInternalAuth != null) {
            internalIDP.setActive(!Boolean.valueOf(disableInternalAuth));
        } else {
            internalIDP.setActive(true);
        }
        provisioning.update(internalIDP);
    }

    private boolean isAmongProviders(String originKey) {
        for (IdentityProvider provider: providers) {
            if (provider.getOriginKey().equals(originKey)) {
                return true;
            }
        }
        return false;
    }

    public void setDefaultPasswordPolicy(PasswordPolicy defaultPasswordPolicy) {
        this.defaultPasswordPolicy = defaultPasswordPolicy;
    }

    public void setDefaultLockoutPolicy(LockoutPolicy defaultLockoutPolicy) {
        this.defaultLockoutPolicy = defaultLockoutPolicy;
    }

	public boolean isDisableInternalUserManagement() {
		return disableInternalUserManagement;
	}

	public void setDisableInternalUserManagement(boolean disableInternalUserManagement) {
		this.disableInternalUserManagement = disableInternalUserManagement;
	}
}
