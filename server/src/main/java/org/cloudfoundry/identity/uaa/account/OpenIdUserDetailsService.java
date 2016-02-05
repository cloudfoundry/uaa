/*******************************************************************************
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

package org.cloudfoundry.identity.uaa.account;

import java.util.List;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationToken;
import org.springframework.util.StringUtils;

/**
 * Custom UserDetailsService which accepts any OpenID user, "registering" new
 * users in a map so they can be welcomed
 * back to the site on subsequent logins.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 * 
 * @since 3.1
 */
public class OpenIdUserDetailsService implements AuthenticationUserDetailsService<OpenIDAuthenticationToken> {

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

    /**
     * Implementation of {@code AuthenticationUserDetailsService} which allows
     * full access to the submitted {@code Authentication} object. Used by the
     * OpenIDAuthenticationProvider.
     */
    @Override
    public UserDetails loadUserDetails(OpenIDAuthenticationToken token) {
        // String id = token.getIdentityUrl();

        String email = null;
        String firstName = null;
        String lastName = null;
        String fullName = null;

        List<OpenIDAttribute> attributes = token.getAttributes();

        for (OpenIDAttribute attribute : attributes) {
            if (attribute.getName().equals("email")) {
                email = attribute.getValues().get(0);
            }

            if (attribute.getName().equals("firstname")) {
                firstName = attribute.getValues().get(0);
            }

            if (attribute.getName().equals("lastname")) {
                lastName = attribute.getValues().get(0);
            }

            if (attribute.getName().equals("fullname")) {
                fullName = attribute.getValues().get(0);
            }
        }

        if (firstName == null && StringUtils.hasText(fullName)) {
            String[] names = fullName.split(" ");
            firstName = names[0];
        }

        if (lastName == null && StringUtils.hasText(fullName)) {
            String[] names = fullName.split(" ");
            lastName = names.length > 1 ? names[1] : "User";
        }

        if (firstName == null && StringUtils.hasText(email)) {
            String[] names = email.split("@");
            firstName = names[0];
        }

        if (lastName == null && StringUtils.hasText(email)) {
            String[] names = email.split("@");
            lastName = names.length > 1 ? names[1] : "User";
        }

        UaaUser user = new UaaUser(email, generator.generate(), email, firstName, lastName);
        return new UaaUserDetails(user);
    }
}
