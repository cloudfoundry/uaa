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

import org.cloudfoundry.identity.uaa.ldap.ExtendedLdapUserDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

import java.util.Map;

public class LdapLoginAuthenticationManager extends ExternalLoginAuthenticationManager {

    private boolean autoAddAuthorities = false;

    @Override
    protected UaaUser getUser(UserDetails details, Map<String, String> info) {
        UaaUser user = super.getUser(details, info);
        if (details instanceof LdapUserDetails) {
            String mail = user.getEmail();
            String origin = getOrigin();
            String externalId = ((LdapUserDetails)details).getDn();
            if (details instanceof ExtendedLdapUserDetails) {
                String[] addrs = ((ExtendedLdapUserDetails)details).getMail();
                if (addrs!=null && addrs.length>0) {
                    mail = addrs[0];
                }
            }
            return new UaaUser(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                mail,
                user.getAuthorities(),
                user.getGivenName(),
                user.getFamilyName(),
                user.getCreated(),
                user.getModified(),
                origin,
                externalId);
        } else {
            logger.warn("Unable to get DN from user. Not an LDAP user:"+details+" of class:"+details.getClass());
            return user.modifySource(getOrigin(), user.getExternalId());
        }
    }

    @Override
    protected UaaUser userAuthenticated(Authentication request, UaaUser user) {
        if (isAutoAddAuthorities()) {
            ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(user, request.getAuthorities());
            publish(event);
            return getUserDatabase().retrieveUserById(user.getId());
        } else {
            return super.userAuthenticated(request, user);
        }
    }

    public boolean isAutoAddAuthorities() {
        return autoAddAuthorities;
    }

    public void setAutoAddAuthorities(boolean autoAddAuthorities) {
        this.autoAddAuthorities = autoAddAuthorities;
    }


}