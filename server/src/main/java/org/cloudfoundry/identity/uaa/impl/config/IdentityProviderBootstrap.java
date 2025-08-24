/*
 * *****************************************************************************
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
package org.cloudfoundry.identity.uaa.impl.config;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderWrapper;
import org.cloudfoundry.identity.uaa.provider.KeystoneIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderData;
import org.cloudfoundry.identity.uaa.util.LdapUtils;
import org.cloudfoundry.identity.uaa.util.UaaMapUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.dao.EmptyResultDataAccessException;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.authentication.SystemAuthentication.SYSTEM_AUTHENTICATION;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_PROPERTY_NAMES;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_PROPERTY_TYPES;

@Slf4j
public class IdentityProviderBootstrap
        implements InitializingBean, ApplicationListener<ContextRefreshedEvent>, ApplicationEventPublisherAware {

    private final IdentityProviderProvisioning provisioning;
    private final List<IdentityProviderWrapper<?>> providers = new LinkedList<>();
    private final Environment environment;
    private final IdentityZoneManager identityZoneManager;
    private BootstrapSamlIdentityProviderData configurator;
    private List<IdentityProviderWrapper> oauthIdpDefintions;
    @Setter
    private Map<String, Object> ldapConfig;
    @Setter
    private Map<String, Object> keystoneConfig;
    @Setter
    private PasswordPolicy defaultPasswordPolicy;
    @Setter
    private LockoutPolicy defaultLockoutPolicy;
    @Getter
    @Setter
    private boolean disableInternalUserManagement;

    @Setter
    private List<String> originsToDelete;
    private ApplicationEventPublisher publisher;

    public IdentityProviderBootstrap(
            final IdentityProviderProvisioning provisioning,
            final IdentityZoneManager identityZoneManager,
            Environment environment) {
        if (provisioning == null) {
            throw new NullPointerException("Constructor argument can't be null.");
        }
        this.provisioning = provisioning;
        this.environment = environment;
        this.identityZoneManager = identityZoneManager;

    }

    private void addOauthProviders() {
        if (oauthIdpDefintions == null) {
            return;
        }
        for (IdentityProviderWrapper<AbstractIdentityProviderDefinition> wrapper : oauthIdpDefintions) {
            validateDuplicateAlias(wrapper.getProvider().getOriginKey());
            providers.add(wrapper);
        }
    }

    public void validateDuplicateAlias(String originKey) {
        for (IdentityProvider<?> provider : providers.stream().map(IdentityProviderWrapper::getProvider).toList()) {
            if (provider.getOriginKey().equals(originKey)) {
                throw new IllegalArgumentException("Provider alias " + originKey + " is not unique.");
            }
        }
    }

    public void setSamlProviders(BootstrapSamlIdentityProviderData configurator) {
        this.configurator = configurator;
    }

    protected void addSamlProviders() {
        if (configurator == null) {
            return;
        }
        for (IdentityProviderWrapper<?> wrapper : configurator.getSamlProviders()) {
            validateDuplicateAlias(wrapper.getProvider().getOriginKey());
            providers.add(wrapper);
        }

    }

    protected void addLdapProvider() {
        boolean ldapProfile = Arrays.asList(environment.getActiveProfiles()).contains(LDAP);
        //the LDAP provider has to be there
        //and we activate, deactivate based on the `ldap` profile presence
        IdentityProvider<LdapIdentityProviderDefinition> provider = new IdentityProvider<>();
        provider.setActive(ldapProfile);
        provider.setOriginKey(LDAP);
        provider.setType(LDAP);
        provider.setName("UAA LDAP Provider");
        Map<String, Object> ldap = new HashMap<>();
        ldap.put(LdapIdentityProviderDefinition.LDAP, ldapConfig);
        LdapIdentityProviderDefinition json = getLdapConfigAsDefinition(ldap);
        provider.setConfig(json);
        provider.setActive(ldapProfile && json.isConfigured());
        /*
          LDAP is a bit tricky. We have a Flyway conversion (2.0.2) that always adds an LDAP provider.
          So we have to assume that if LDAP config == null, then we should override it
         */
        boolean override = ldapConfig == null || ldapConfig.get("override") == null || (boolean) ldapConfig.get("override");
        if (!override) {
            IdentityProvider<AbstractIdentityProviderDefinition> existing = getProviderByOriginIgnoreActiveFlag(LDAP, IdentityZone.getUaaZoneId());
            override = existing == null || existing.getConfig() == null;
        }
        IdentityProviderWrapper<LdapIdentityProviderDefinition> wrapper = new IdentityProviderWrapper<>(provider);
        wrapper.setOverride(override);
        providers.add(wrapper);
    }

    protected LdapIdentityProviderDefinition getLdapConfigAsDefinition(Map<String, Object> ldapConfig) {
        ldapConfig = UaaMapUtils.flatten(ldapConfig);
        populateLdapEnvironment(ldapConfig);
        if (ldapConfig.isEmpty()) {
            return new LdapIdentityProviderDefinition();
        }
        return LdapUtils.fromConfig(ldapConfig);
    }

    protected void populateLdapEnvironment(Map<String, Object> ldapConfig) {
        //this method reads the environment and overwrites values (needed by LdapMockMvcTests that overrides properties through env)
        AbstractEnvironment env = (AbstractEnvironment) environment;
        //these are our known complex data structures in the properties
        for (String property : LDAP_PROPERTY_NAMES) {
            if (env.containsProperty(property) && LDAP_PROPERTY_TYPES.get(property) != null) {
                ldapConfig.put(property, env.getProperty(property, LDAP_PROPERTY_TYPES.get(property)));
            }
        }

        //but we can also have string properties like ldap.attributeMappings.user.attribute.mapToAttributeName=mapFromAttributeName
        Map<String, Object> stringProperties = UaaMapUtils.getPropertiesStartingWith(env, "ldap.");
        for (Map.Entry<String, Object> entry : stringProperties.entrySet()) {
            if (!LDAP_PROPERTY_NAMES.contains(entry.getKey())) {
                ldapConfig.put(entry.getKey(), entry.getValue());
            }
        }
    }

    protected AbstractIdentityProviderDefinition getKeystoneDefinition(Map<String, Object> config) {
        return new KeystoneIdentityProviderDefinition(config);
    }

    protected void addKeystoneProvider() {
        boolean keystoneProfile = Arrays.asList(environment.getActiveProfiles()).contains(OriginKeys.KEYSTONE);
        if (keystoneConfig != null || keystoneProfile) {
            boolean active = keystoneProfile && keystoneConfig != null;
            IdentityProvider<AbstractIdentityProviderDefinition> provider = new IdentityProvider<>();
            provider.setOriginKey(OriginKeys.KEYSTONE);
            provider.setType(OriginKeys.KEYSTONE);
            provider.setName("UAA Keystone Provider");
            provider.setActive(active);
            provider.setConfig(getKeystoneDefinition(keystoneConfig));
            providers.add(new IdentityProviderWrapper<>(provider));
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        deleteIdentityProviders(IdentityZone.getUaaZoneId());
    }

    @Override
    public void afterPropertiesSet() throws Exception {

        providers.clear();
        addLdapProvider();
        addSamlProviders();
        addOauthProviders();
        addKeystoneProvider();

        String zoneId = IdentityZone.getUaaZoneId();

        for (IdentityProviderWrapper<?> wrapper : providers) {
            IdentityProvider<?> provider = wrapper.getProvider();
            if (getOriginsToDelete().contains(provider.getOriginKey())) {
                //dont process origins slated for deletion
                continue;
            }
            IdentityProvider<AbstractIdentityProviderDefinition> existing = getProviderByOriginIgnoreActiveFlag(provider.getOriginKey(), zoneId);
            provider.setIdentityZoneId(zoneId);
            if (existing == null) {
                provisioning.create(provider, zoneId);
            } else if (wrapper.isOverride()) {
                provider.setId(existing.getId());
                provider.setCreated(existing.getCreated());
                provider.setVersion(existing.getVersion());
                provider.setLastModified(new Date(System.currentTimeMillis()));
                provisioning.update(provider, zoneId);
            }
        }
        updateDefaultZoneUaaIDP();
    }

    public IdentityProvider<AbstractIdentityProviderDefinition> getProviderByOriginIgnoreActiveFlag(String origin, String zoneId) {
        try {
            return provisioning.retrieveByOriginIgnoreActiveFlag(origin, zoneId);
        } catch (EmptyResultDataAccessException ignored) {
            return null;
        }
    }

    private void deleteIdentityProviders(String zoneId) {
        for (String origin : getOriginsToDelete()) {
            if (!UAA.equals(origin) && !LDAP.equals(origin)) {
                log.debug("Attempting to deactivating identity provider: {}", origin);
                IdentityProvider<AbstractIdentityProviderDefinition> provider = getProviderByOriginIgnoreActiveFlag(origin, zoneId);
                //delete provider
                if (provider != null) {
                    EntityDeletedEvent<IdentityProvider<AbstractIdentityProviderDefinition>> event = new EntityDeletedEvent<>(provider, SYSTEM_AUTHENTICATION, identityZoneManager.getCurrentIdentityZoneId());
                    if (this.publisher != null) {
                        publisher.publishEvent(event);
                        log.debug("Identity provider deactivated: {}", origin);
                    } else {
                        log.warn("Unable to delete identity provider with origin '{}', no application publisher", origin);
                    }
                }
            }
        }
    }

    protected void updateDefaultZoneUaaIDP() {
        String zoneId = IdentityZone.getUaaZoneId();
        IdentityProvider<AbstractIdentityProviderDefinition> internalIDP = getProviderByOriginIgnoreActiveFlag(UAA, IdentityZone.getUaaZoneId());
        UaaIdentityProviderDefinition identityProviderDefinition = new UaaIdentityProviderDefinition(defaultPasswordPolicy, defaultLockoutPolicy, disableInternalUserManagement);
        internalIDP.setConfig(identityProviderDefinition);
        String disableInternalAuth = environment.getProperty("disableInternalAuth");
        internalIDP.setActive(!getBooleanValue(disableInternalAuth, false));
        provisioning.update(internalIDP, zoneId);
    }

    protected boolean getBooleanValue(String s, boolean defaultValue) {
        if (s != null) {
            return Boolean.valueOf(s);
        } else {
            return defaultValue;
        }
    }

    public void setOauthIdpDefinitions(List<IdentityProviderWrapper> oauthIdpDefintions) {
        this.oauthIdpDefintions = oauthIdpDefintions;
    }

    public List<String> getOriginsToDelete() {
        return ofNullable(originsToDelete).orElse(emptyList());
    }
}
