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
package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaLoginHint;
import org.cloudfoundry.identity.uaa.authentication.manager.ChainedAuthenticationManager.AuthenticationManagerConfiguration;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class DynamicZoneAwareAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware {

    private final IdentityProviderProvisioning provisioning;
    private final AuthenticationManager internalUaaAuthenticationManager;
    private final ConcurrentMap<IdentityZone, DynamicLdapAuthenticationManager> ldapAuthManagers = new ConcurrentHashMap<>();
    private final ScimGroupExternalMembershipManager scimGroupExternalMembershipManager;
    private final ScimGroupProvisioning scimGroupProvisioning;
    private final LdapLoginAuthenticationManager ldapLoginAuthenticationManager;
    private ApplicationEventPublisher eventPublisher;

    public DynamicZoneAwareAuthenticationManager(final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning provisioning,
            AuthenticationManager internalUaaAuthenticationManager,
            ScimGroupExternalMembershipManager scimGroupExternalMembershipManager,
            ScimGroupProvisioning scimGroupProvisioning,
            LdapLoginAuthenticationManager ldapLoginAuthenticationManager) {
        this.provisioning = provisioning;
        this.internalUaaAuthenticationManager = internalUaaAuthenticationManager;
        this.scimGroupExternalMembershipManager = scimGroupExternalMembershipManager;
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.ldapLoginAuthenticationManager = ldapLoginAuthenticationManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        IdentityZone zone = IdentityZoneHolder.get();
        //chain it exactly like the UAA
        UaaLoginHint loginHint = extractLoginHint(authentication);
        return getChainedAuthenticationManager(zone, loginHint).authenticate(authentication);
    }

    protected UaaLoginHint extractLoginHint(Authentication authentication) {
        UaaLoginHint loginHint = null;
        if (authentication != null && authentication.getDetails() instanceof UaaAuthenticationDetails) {
            UaaAuthenticationDetails uaaAuthenticationDetails = (UaaAuthenticationDetails) authentication.getDetails();
            loginHint = uaaAuthenticationDetails.getLoginHint();
        }
        return loginHint;
    }

    protected boolean setLoginHint(Authentication authentication, UaaLoginHint loginHint) {
        if (authentication != null && authentication.getDetails() instanceof UaaAuthenticationDetails) {
            UaaAuthenticationDetails uaaAuthenticationDetails = (UaaAuthenticationDetails) authentication.getDetails();
            uaaAuthenticationDetails.setLoginHint(loginHint);
            return true;
        }
        return false;
    }

    protected ChainedAuthenticationManager getChainedAuthenticationManager(IdentityZone zone, UaaLoginHint loginHint) {
        IdentityProvider ldapProvider = getProvider(OriginKeys.LDAP, zone);
        IdentityProvider uaaProvider = getProvider(OriginKeys.UAA, zone);

        List<AuthenticationManagerConfiguration> delegates = new LinkedList<>();

        String origin = loginHint == null ? null : loginHint.getOrigin();
        if (uaaProvider.isActive() && (origin == null || "uaa".equals(origin))) {
            AuthenticationManagerConfiguration uaaConfig = new AuthenticationManagerConfiguration(internalUaaAuthenticationManager, null);
            uaaConfig.setStopIf(
                    AccountNotVerifiedException.class,
                    AuthenticationPolicyRejectionException.class,
                    PasswordChangeRequiredException.class
            );
            delegates.add(uaaConfig);
        }

        if (ldapProvider.isActive() && (origin == null || "ldap".equals(origin))) {
            //has LDAP IDP config changed since last time?
            DynamicLdapAuthenticationManager existing = getLdapAuthenticationManager(zone, ldapProvider);
            if (!existing.getDefinition().equals(ldapProvider.getConfig())) {
                ldapAuthManagers.remove(zone);
                existing.destroy();
            }
            DynamicLdapAuthenticationManager ldapAuthenticationManager = getLdapAuthenticationManager(zone, ldapProvider);
            AuthenticationManagerConfiguration ldapConfig =
                    new AuthenticationManagerConfiguration(ldapAuthenticationManager,
                            delegates.isEmpty() ? null : ChainedAuthenticationManager.IF_PREVIOUS_FALSE);
            delegates.add(ldapConfig);
        }

        if (delegates.isEmpty() && origin != null) {
            throw new ProviderNotFoundException("The origin provided in the login hint is invalid.");
        }

        ChainedAuthenticationManager result = new ChainedAuthenticationManager();
        result.setDelegates(delegates.toArray(new AuthenticationManagerConfiguration[0]));
        return result;
    }

    protected IdentityProvider getProvider(String origin, IdentityZone zone) {
        try {
            IdentityProvider result = provisioning.retrieveByOrigin(origin, zone.getId());
            if (result != null) {
                return result;
            }
        } catch (EmptyResultDataAccessException ignored) {
        }
        IdentityProvider provider = new IdentityProvider();
        provider.setOriginKey(origin);
        provider.setActive(false);
        return provider;
    }

    public DynamicLdapAuthenticationManager getLdapAuthenticationManager(IdentityZone zone, IdentityProvider provider) {
        DynamicLdapAuthenticationManager ldapMgr = ldapAuthManagers.get(zone);
        if (ldapMgr != null) {
            return ldapMgr;
        }
        LdapIdentityProviderDefinition definition = ObjectUtils.castInstance(provider.getConfig(), LdapIdentityProviderDefinition.class);
        if (definition == null || !definition.isConfigured()) {
            throw new IllegalArgumentException("LDAP provider not configured ID:" + provider.getId());
        }
        ldapMgr = new DynamicLdapAuthenticationManager(definition,
                scimGroupExternalMembershipManager,
                scimGroupProvisioning,
                ldapLoginAuthenticationManager);
        ldapMgr.setApplicationEventPublisher(eventPublisher);
        ldapAuthManagers.putIfAbsent(zone, ldapMgr);
        return ldapAuthManagers.get(zone);
    }

    public void destroy() {
        for (Map.Entry<IdentityZone, DynamicLdapAuthenticationManager> entry : ldapAuthManagers.entrySet()) {
            entry.getValue().destroy();
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher;
    }
}
