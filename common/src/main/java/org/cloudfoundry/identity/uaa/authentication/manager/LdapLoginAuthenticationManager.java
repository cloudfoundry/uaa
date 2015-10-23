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
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.Date;

public class LdapLoginAuthenticationManager extends ExternalLoginAuthenticationManager {

    private boolean autoAddAuthorities = false;

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
