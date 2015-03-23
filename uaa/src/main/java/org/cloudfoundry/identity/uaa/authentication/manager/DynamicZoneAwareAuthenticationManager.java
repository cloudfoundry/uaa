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
package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class DynamicZoneAwareAuthenticationManager implements AuthenticationManager {

    private final IdentityProviderProvisioning provisioning;
    private final AuthenticationManager internalUaaAuthenticationManager;
    private final AuthenticationManager authzAuthenticationMgr;
    private final ConcurrentMap<IdentityZone, DynamicLdapAuthenticationManager> ldapAuthManagers = new ConcurrentHashMap<>();
    private final ScimGroupExternalMembershipManager scimGroupExternalMembershipManager;
    private final ScimGroupProvisioning scimGroupProvisioning;
    private final LdapLoginAuthenticationManager ldapLoginAuthenticationManager;

    public DynamicZoneAwareAuthenticationManager(AuthenticationManager authzAuthenticationMgr,
                                                 IdentityProviderProvisioning provisioning,
                                                 AuthenticationManager internalUaaAuthenticationManager,
                                                 ScimGroupExternalMembershipManager scimGroupExternalMembershipManager,
                                                 ScimGroupProvisioning scimGroupProvisioning,
                                                 LdapLoginAuthenticationManager ldapLoginAuthenticationManager) {
        this.authzAuthenticationMgr = authzAuthenticationMgr;
        this.provisioning = provisioning;
        this.internalUaaAuthenticationManager = internalUaaAuthenticationManager;
        this.scimGroupExternalMembershipManager = scimGroupExternalMembershipManager;
        this.scimGroupProvisioning = scimGroupProvisioning;
        this.ldapLoginAuthenticationManager = ldapLoginAuthenticationManager;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        IdentityZone zone = IdentityZoneHolder.get();
        //if zone==uaa just use the authzAuthenticationMgr bean
        if (zone.equals(IdentityZone.getUaa())) {
            return authzAuthenticationMgr.authenticate(authentication);
        } else {
            //else if ldap IDP present and enabled - create ldap auth manager
            try {
                IdentityProvider ldapProvider = provisioning.retrieveByOrigin(Origin.LDAP, IdentityZoneHolder.get().getId());
                if (ldapProvider.isActive()) {
                    //has LDAP IDP config changed since last time?
                    DynamicLdapAuthenticationManager existing = getLdapAuthenticationManager(zone, ldapProvider);
                    if (!existing.getDefinition().equals(ldapProvider.getConfigValue(LdapIdentityProviderDefinition.class))) {
                        ldapAuthManagers.remove(zone);
                        existing.destroy();
                    }
                    return getLdapAuthenticationManager(zone, ldapProvider).authenticate(authentication);
                }
            } catch (EmptyResultDataAccessException noLdapProviderFound) {
            }
            //else use uaaAuthenticationMgr bean (already zone aware)
            return internalUaaAuthenticationManager.authenticate(authentication);
        }
    }

    protected DynamicLdapAuthenticationManager getLdapAuthenticationManager(IdentityZone zone, IdentityProvider provider) {
        DynamicLdapAuthenticationManager ldapMgr = ldapAuthManagers.get(zone);
        if (ldapMgr!=null) {
            return ldapMgr;
        }
        ldapMgr = new DynamicLdapAuthenticationManager(provider.getConfigValue(LdapIdentityProviderDefinition.class),
            scimGroupExternalMembershipManager,
            scimGroupProvisioning,
            ldapLoginAuthenticationManager);
        ldapAuthManagers.putIfAbsent(zone, ldapMgr);
        return ldapAuthManagers.get(zone);
    }

    public void destroy() {
        for (Map.Entry<IdentityZone, DynamicLdapAuthenticationManager> entry : ldapAuthManagers.entrySet()) {
            entry.getValue().destroy();
        }
    }
}
