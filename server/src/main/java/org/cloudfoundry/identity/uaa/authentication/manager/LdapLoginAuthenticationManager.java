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

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserDetails;
import org.cloudfoundry.identity.uaa.provider.ldap.extension.LdapAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.MultiValueMap;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Collections.emptyList;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.retainAllMatches;

public class LdapLoginAuthenticationManager extends ExternalLoginAuthenticationManager {

    protected static Logger logger = LoggerFactory.getLogger(LdapLoginAuthenticationManager.class);

    public LdapLoginAuthenticationManager(final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning providerProvisioning) {
        super(providerProvisioning);
    }

    @Override
    protected void populateAuthenticationAttributes(UaaAuthentication authentication, Authentication request, Object authenticationData) {
        super.populateAuthenticationAttributes(authentication, request, authenticationData);
        authentication.getAuthenticationMethods().add("pwd");
    }

    @Override
    protected MultiValueMap<String, String> getUserAttributes(UserDetails request) {
        MultiValueMap<String, String> result = super.getUserAttributes(request);
        logger.debug("Mapping custom attributes for origin:{} and zone:{}", getOrigin(), IdentityZoneHolder.get().getId());
        if (getProviderProvisioning() != null) {
            IdentityProvider provider = getProviderProvisioning().retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
            if (request instanceof ExtendedLdapUserDetails ldapDetails) {
                LdapIdentityProviderDefinition ldapIdentityProviderDefinition = ObjectUtils.castInstance(provider.getConfig(), LdapIdentityProviderDefinition.class);
                Map<String, Object> providerMappings = ldapIdentityProviderDefinition.getAttributeMappings();
                for (Map.Entry<String, Object> entry : providerMappings.entrySet()) {
                    if (entry.getKey().startsWith(USER_ATTRIBUTE_PREFIX) && entry.getValue() != null) {
                        String key = entry.getKey().substring(USER_ATTRIBUTE_PREFIX.length());
                        String[] values = ldapDetails.getAttribute((String) entry.getValue(), false);
                        if (values != null && values.length > 0) {
                            result.put(key, Arrays.asList(values));
                            logger.debug("Mappcustom attribute key:{} and value:{}", key, result.get(key));
                        }
                    }
                }
            }
        } else {
            logger.debug("Did not find custom attribute configuration for origin:{} and zone:{}", getOrigin(), IdentityZoneHolder.get().getId());
        }
        return result;
    }

    @Override
    protected List<String> getExternalUserAuthorities(UserDetails request) {
        List<String> result = super.getExternalUserAuthorities(request);
        if (getProviderProvisioning() != null) {
            IdentityProvider provider = getProviderProvisioning().retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
            LdapIdentityProviderDefinition ldapIdentityProviderDefinition = ObjectUtils.castInstance(provider.getConfig(), LdapIdentityProviderDefinition.class);
            List<String> externalWhiteList = ldapIdentityProviderDefinition.getExternalGroupsWhitelist();
            result = new ArrayList<>(retainAllMatches(getAuthoritesAsNames(request.getAuthorities()), externalWhiteList));
        }
        return result;
    }

    protected Set<String> getAuthoritesAsNames(Collection<? extends GrantedAuthority> authorities) {
        Set<String> result = new HashSet<>();
        authorities = new LinkedList<>(authorities != null ? authorities : emptyList());
        for (GrantedAuthority a : authorities) {
            if (a instanceof LdapAuthority la) {
                String[] groupNames = la.getAttributeValues("cn");
                if (groupNames != null) {
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
        if (request.getPrincipal() != null && request.getPrincipal() instanceof ExtendedLdapUserDetails) {
            if (haveUserAttributesChanged(userFromDb, userFromRequest)) {
                userFromDb = userFromDb.modifyAttributes(userFromRequest.getEmail(),
                                userFromRequest.getGivenName(),
                                userFromRequest.getFamilyName(),
                                userFromRequest.getPhoneNumber(),
                                userFromRequest.getExternalId(),
                                userFromDb.isVerified() || userFromRequest.isVerified())
                        .modifyUsername(userFromRequest.getUsername());
                userModified = true;
            }
        }
        ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(userFromDb, userModified, request.getAuthorities(), isAutoAddAuthorities());
        publish(event);
        return getUserDatabase().retrieveUserById(userFromDb.getId());
    }

    protected boolean isAutoAddAuthorities() {
        Boolean result = true;
        if (getProviderProvisioning() != null) {
            IdentityProvider provider = getProviderProvisioning().retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
            LdapIdentityProviderDefinition ldapIdentityProviderDefinition = ObjectUtils.castInstance(provider.getConfig(), LdapIdentityProviderDefinition.class);
            if (ldapIdentityProviderDefinition != null) {
                result = ldapIdentityProviderDefinition.isAutoAddGroups();
            }
        }
        return result == null || result;
    }

    @Override
    protected boolean isAddNewShadowUser() {
        boolean result = true;
        if (getProviderProvisioning() != null) {
            IdentityProvider provider = getProviderProvisioning().retrieveByOrigin(getOrigin(), IdentityZoneHolder.get().getId());
            LdapIdentityProviderDefinition ldapIdentityProviderDefinition = ObjectUtils.castInstance(provider.getConfig(), LdapIdentityProviderDefinition.class);
            if (ldapIdentityProviderDefinition != null) {
                result = ldapIdentityProviderDefinition.isAddShadowUserOnLogin();
            }
        }
        return result;
    }
}
