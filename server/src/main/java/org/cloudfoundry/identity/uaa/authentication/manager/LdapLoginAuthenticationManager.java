/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication.manager;

import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserDetails;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.ldap.extension.LdapAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.EMPTY_LIST;

public class LdapLoginAuthenticationManager extends ExternalLoginAuthenticationManager {

    public static final String USER_ATTRIBUTE_PREFIX = "user.attribute.";
    private IdentityProviderProvisioning provisioning;

    public void setProvisioning(IdentityProviderProvisioning provisioning) {
        this.provisioning = provisioning;
    }

    @Override
    protected MultiValueMap<String, String> getUserAttributes(UserDetails request) {
        MultiValueMap<String, String> result = super.getUserAttributes(request);
        if (provisioning!=null) {
            IdentityProvider provider = provisioning.retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
            if (request instanceof ExtendedLdapUserDetails) {
                ExtendedLdapUserDetails ldapDetails = ((ExtendedLdapUserDetails) request);
                LdapIdentityProviderDefinition ldapIdentityProviderDefinition = ObjectUtils.castInstance(provider.getConfig(),LdapIdentityProviderDefinition.class);
                Map<String, Object> providerMappings = ldapIdentityProviderDefinition.getAttributeMappings();
                for (Map.Entry<String, Object> entry : providerMappings.entrySet()) {
                    if (entry.getKey().startsWith(USER_ATTRIBUTE_PREFIX) && entry.getValue() != null) {
                        String key = entry.getKey().substring(USER_ATTRIBUTE_PREFIX.length());
                        String[] values = ldapDetails.getAttribute((String) entry.getValue(), false);
                        if (values != null && values.length > 0) {
                            result.put(key, Arrays.asList(values));
                        }
                    }
                }
            }
        }
        return result;
    }

    @Override
    protected List<String> getExternalUserAuthorities(UserDetails request) {
        List<String> result = super.getExternalUserAuthorities(request);
        if (provisioning!=null) {
            IdentityProvider provider = provisioning.retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
            LdapIdentityProviderDefinition ldapIdentityProviderDefinition = ObjectUtils.castInstance(provider.getConfig(),LdapIdentityProviderDefinition.class);
            List<String> externalWhiteList = ldapIdentityProviderDefinition.getExternalGroupsWhitelist();
            result = new LinkedList<>(getAuthoritesAsNames(request.getAuthorities()));
            result.retainAll(externalWhiteList);
        }
        return result;
    }

    protected Set<String> getAuthoritesAsNames(Collection<? extends GrantedAuthority> authorities) {
        Set<String> result = new HashSet<>();
        authorities = new LinkedList(authorities!=null?authorities: EMPTY_LIST);
        for (GrantedAuthority a : authorities) {
            if (a instanceof LdapAuthority) {
                LdapAuthority la = (LdapAuthority)a;
                String[] groupNames = la.getAttributeValues("cn");
                if (groupNames!=null) {
                    result.addAll(Arrays.asList(groupNames));
                }
            }
        }
        return result;
    }

    @Override
    protected UaaUser userAuthenticated(Authentication request, UaaUser userFromRequest, UaaUser userFromDb) {
        boolean userModified = false;
        //we must check and see if the email address has changed between authentications
        if (request.getPrincipal() !=null && request.getPrincipal() instanceof ExtendedLdapUserDetails) {
            if (haveUserAttributesChanged(userFromDb, userFromRequest)) {
                userFromDb = userFromDb.modifyAttributes(userFromRequest.getEmail(), userFromRequest.getGivenName(), userFromRequest.getFamilyName(), userFromRequest.getPhoneNumber()).modifyUsername(userFromRequest.getUsername());
                userModified = true;
            }
        }
        ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(userFromDb, userModified, request.getAuthorities(), isAutoAddAuthorities());
        publish(event);
        return getUserDatabase().retrieveUserById(userFromDb.getId());
    }

    protected boolean isAutoAddAuthorities() {
        Boolean result = true;
        if (provisioning!=null) {
            IdentityProvider provider = provisioning.retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
            LdapIdentityProviderDefinition ldapIdentityProviderDefinition = ObjectUtils.castInstance(provider.getConfig(), LdapIdentityProviderDefinition.class);
            if (ldapIdentityProviderDefinition!=null) {
                result = ldapIdentityProviderDefinition.isAutoAddGroups();
            }
        }
        return result!=null ? result.booleanValue() : true;
    }

}
