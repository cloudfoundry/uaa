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
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
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
            String mail = getEmail(user, (LdapUserDetails)details);
            String origin = getOrigin();
            String externalId = ((LdapUserDetails)details).getDn();
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
                externalId,
                false,
                IdentityZoneHolder.get().getId(),
                null);
        } else {
            logger.warn("Unable to get DN from user. Not an LDAP user:"+details+" of class:"+details.getClass());
            return user.modifySource(getOrigin(), user.getExternalId());
        }
    }

    protected String getEmail(UaaUser user, LdapUserDetails details) {
        String mail = user.getEmail();
        if (details instanceof ExtendedLdapUserDetails) {
            String[] emails = ((ExtendedLdapUserDetails)details).getMail();
            if (emails!=null && emails.length>0) {
                mail = emails[0];
            }
        }
        return mail;
    }

    @Override
    protected UaaUser userAuthenticated(Authentication request, UaaUser user) {
        //we must check and see if the email address has changed between authentications
        if (request.getPrincipal() !=null && request.getPrincipal() instanceof ExtendedLdapUserDetails) {
            ExtendedLdapUserDetails details = (ExtendedLdapUserDetails)request.getPrincipal();
            UaaUser fromRequest = getUser(details, getExtendedAuthorizationInfo(request));
            if (fromRequest.getEmail()!=null && !fromRequest.getEmail().equals(user.getEmail())) {
                user = user.modifyEmail(fromRequest.getEmail());
            }
        }
        ExternalGroupAuthorizationEvent event = new ExternalGroupAuthorizationEvent(user, request.getAuthorities(), isAutoAddAuthorities());
        publish(event);
        return getUserDatabase().retrieveUserById(user.getId());
    }

    public boolean isAutoAddAuthorities() {
        return autoAddAuthorities;
    }

    public void setAutoAddAuthorities(boolean autoAddAuthorities) {
        this.autoAddAuthorities = autoAddAuthorities;
    }


}