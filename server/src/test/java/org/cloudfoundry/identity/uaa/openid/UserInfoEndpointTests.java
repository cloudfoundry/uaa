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
package org.cloudfoundry.identity.uaa.openid;

import static org.junit.Assert.assertEquals;

import java.util.Collections;
import java.util.Date;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.account.UserInfoEndpoint;
import org.cloudfoundry.identity.uaa.account.UserInfoResponse;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * 
 */
public class UserInfoEndpointTests {

    private UserInfoEndpoint endpoint = new UserInfoEndpoint();

    private final UaaUser user = new UaaUser(new UaaUserPrototype()
                    .withId("12345")
                    .withPhoneNumber("8505551234")
                    .withUsername("olds")
                    .withPassword("")
                    .withEmail("olds@vmware.com")
                    .withFamilyName("Olds")
                    .withGivenName("Dale")
                    .withCreated(new Date())
                    .withModified(new Date())
                    .withAuthorities(UaaAuthority.USER_AUTHORITIES)
                    .withOrigin(OriginKeys.UAA)
                    .withExternalId("externalId")
                    .withVerified(false)
                    .withZoneId(IdentityZoneHolder.get().getId())
                    .withSalt("12345")
                    .withPasswordLastModified(new Date()));
    private InMemoryUaaUserDatabase userDatabase = new InMemoryUaaUserDatabase(Collections.singleton(user));

    public UserInfoEndpointTests() {
        endpoint.setUserDatabase(userDatabase);
    }

    @Test
    public void testSunnyDay() {
        UaaUser user = userDatabase.retrieveUserByName("olds", OriginKeys.UAA);
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(user.getId(), "olds",
                        "olds@vmware.com");
        UserInfoResponse map = endpoint.loginInfo(new OAuth2Authentication(null, authentication));
        assertEquals("olds", map.getUsername());
        assertEquals("Dale Olds", map.getFullName());
        assertEquals("olds@vmware.com", map.getEmail());
        assertEquals("8505551234", map.getPhoneNumber());
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testMissingUser() {
        UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication("nonexist-id", "Dale",
                        "olds@vmware.com");
        UserInfoResponse map = endpoint.loginInfo(new OAuth2Authentication(null, authentication));
    }

}
