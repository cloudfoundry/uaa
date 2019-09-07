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

package org.cloudfoundry.identity.uaa.login;

import static org.junit.Assert.assertSame;

import org.cloudfoundry.identity.uaa.authentication.manager.UsernamePasswordExtractingAuthenticationManager;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author Dave Syer
 * 
 */
public class UsernamePasswordExtractingAuthenticationManagerTests {

    private AuthenticationManager delegate = Mockito.mock(AuthenticationManager.class);

    private UsernamePasswordExtractingAuthenticationManager manager = new UsernamePasswordExtractingAuthenticationManager(
                    delegate);

    @Before
    public void setUp() {
        SecurityContextHolder.clearContext();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testAuthenticate() {
        Authentication expected = new TestingAuthenticationToken("bar", "foo",
                        AuthorityUtils.commaSeparatedStringToAuthorityList("USER"));
        Mockito.when(delegate.authenticate(ArgumentMatchers.any(UsernamePasswordAuthenticationToken.class)))
                        .thenReturn(expected);
        Authentication output = manager.authenticate(new TestingAuthenticationToken("foo", "bar"));
        assertSame(expected, output);
    }

    @Test
    public void testUsernamePassword() {
        Authentication expected = new UsernamePasswordAuthenticationToken("bar", "foo",
                        AuthorityUtils.commaSeparatedStringToAuthorityList("USER"));
        Mockito.when(delegate.authenticate(ArgumentMatchers.any(UsernamePasswordAuthenticationToken.class)))
                        .thenReturn(expected);
        Authentication output = manager.authenticate(expected);
        assertSame(expected, output);
    }

}
