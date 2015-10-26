/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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
import org.cloudfoundry.identity.uaa.ldap.ExtendedLdapUserDetails;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.Map;

public class LdapLoginAuthenticationManager extends ExternalLoginAuthenticationManager {

    public static final String USER_ATTRIBUTE_PREFIX = "user.attribute.";
    private boolean autoAddAuthorities = false;
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
                for (Map.Entry<String, Object> entry : provider.getConfigValue(LdapIdentityProviderDefinition.class).getAttributeMappings().entrySet()) {
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
    protected UaaUser userAuthenticated(Authentication request, UaaUser user) {
        boolean userModified = false;
        //we must check and see if the email address has changed between authentications
        if (request.getPrincipal() !=null && request.getPrincipal() instanceof ExtendedLdapUserDetails) {
            UaaUser fromRequest = getUser(request);
            if (haveUserAttributesChanged(user, fromRequest)) {
                user = user.modifyAttributes(fromRequest.getEmail(), fromRequest.getGivenName(), fromRequest.getFamilyName(), fromRequest.getPhoneNumber());
                userModified = true;
            }
        }
        ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(user, userModified, request.getAuthorities(), isAutoAddAuthorities());
        publish(event);
        return getUserDatabase().retrieveUserById(user.getId());
    }

    public boolean isAutoAddAuthorities() {
        return autoAddAuthorities;
    }

    public void setAutoAddAuthorities(boolean autoAddAuthorities) {
        this.autoAddAuthorities = autoAddAuthorities;
    }

    private boolean haveUserAttributesChanged(UaaUser existingUser, UaaUser user) {
        if (!StringUtils.equals(existingUser.getGivenName(), user.getGivenName()) || !StringUtils.equals(existingUser.getFamilyName(), user.getFamilyName()) ||
                !StringUtils.equals(existingUser.getPhoneNumber(), user.getPhoneNumber()) || !StringUtils.equals(existingUser.getEmail(), user.getEmail())) {
            return true;
        }
        return false;
    }
}
