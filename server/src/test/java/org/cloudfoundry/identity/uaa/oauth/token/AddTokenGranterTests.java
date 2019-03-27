/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static java.util.Collections.emptyList;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

public class AddTokenGranterTests {


    private CompositeTokenGranter compositeTokenGranter;
    private UserTokenGranter userTokenGranter;

    @Before
    public void setup() {
        compositeTokenGranter = new CompositeTokenGranter(emptyList());
        userTokenGranter = new UserTokenGranter(
            mock(AuthorizationServerTokenServices.class),
            mock(MultitenantClientServices.class),
            mock(OAuth2RequestFactory.class),
            mock(RevocableTokenProvisioning.class)
        );
    }


    @Test
    public void happy_day() {
        new AddTokenGranter(userTokenGranter, compositeTokenGranter);
        List<TokenGranter> granterList = (List<TokenGranter>) ReflectionTestUtils.getField(compositeTokenGranter, "tokenGranters");
        assertThat("User token compositeTokenGranter should have been added to the list.", granterList, Matchers.contains(userTokenGranter));
    }

    @Test(expected = IllegalArgumentException.class)
    public void invalid_class_used() {
        new AddTokenGranter(userTokenGranter, mock(TokenGranter.class));
    }
}