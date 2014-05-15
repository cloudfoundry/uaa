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

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

import java.util.Map;

public class LdapLoginAuthenticationManager extends ExternalLoginAuthenticationManager {


    @Override
    protected UaaUser getUser(UserDetails details, Map<String, String> info) {
        UaaUser user = super.getUser(details, info);
        if (details instanceof LdapUserDetails) {
            return user.modifySource(getOrigin(), ((LdapUserDetails)details).getDn());
        } else {
            logger.warn("Unable to get DN from user. Not an LDAP user:"+details+" of class:"+details.getClass());
            return user;
        }
    }
}