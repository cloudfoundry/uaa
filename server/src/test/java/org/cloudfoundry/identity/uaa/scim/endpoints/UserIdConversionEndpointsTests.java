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

package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.Collections;

import static junit.framework.Assert.assertTrue;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * @author Dave Syer
 * @author Luke Taylor
 *
 */
public class UserIdConversionEndpointsTests {

    @Rule
    public ExpectedException expected = ExpectedException.none();

    private IdentityProviderProvisioning provisioning = Mockito.mock(IdentityProviderProvisioning.class);

    private UserIdConversionEndpoints endpoints;

    private SecurityContextAccessor mockSecurityContextAccessor;

    private ScimUserEndpoints scimUserEndpoints = Mockito.mock(ScimUserEndpoints.class);

    @SuppressWarnings("rawtypes")
    private Collection authorities = AuthorityUtils
                    .commaSeparatedStringToAuthorityList("orgs.foo,uaa.user");

    @SuppressWarnings("unchecked")
    @Before
    public void init() {
        mockSecurityContextAccessor = Mockito.mock(SecurityContextAccessor.class);
        endpoints = new UserIdConversionEndpoints(provisioning, mockSecurityContextAccessor, scimUserEndpoints);
        //endpoints.setScimUserEndpoints(scimUserEndpoints);
        endpoints.setEnabled(true);
        when(mockSecurityContextAccessor.getAuthorities()).thenReturn(authorities);
        when(mockSecurityContextAccessor.getAuthenticationInfo()).thenReturn("mock object");
        when(provisioning.retrieveActive(anyString())).thenReturn(Collections.singletonList(MultitenancyFixture.identityProvider("test-origin", "uaa")));
    }

    @Test
    public void testHappyDay() {
        endpoints.findUsers("userName eq \"marissa\"", "ascending", 0, 100, false);
    }

    @Test
    public void testBadFieldInFilter() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Invalid filter"));
        endpoints.findUsers("emails.value eq \"foo@bar.org\"", "ascending", 0, 100, false);
    }

    @Test
    public void testBadFilterWithGroup() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Invalid filter"));
        endpoints.findUsers("groups.display eq \"foo\"", "ascending", 0, 100, false);
    }

    @Test
    public void testGoodFilter1() {
        endpoints.findUsers("(id eq \"foo\" or username eq \"bar\") and origin eq \"uaa\"", "ascending", 0, 100, false);
    }

    @Test
    public void testBadFilter1() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Wildcards are not allowed in filter."));
        endpoints.findUsers("id co \"foo\"", "ascending", 0, 100, false);
    }

    @Test
    public void testBadFilter2() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Invalid filter"));
        endpoints.findUsers("id sq \"foo\"", "ascending", 0, 100, false);
    }

    @Test
    public void testBadFilter3() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Wildcards are not allowed in filter."));
        endpoints.findUsers("id sw \"foo\"", "ascending", 0, 100, false);
    }

    @Test
    public void testBadFilter4() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Wildcards are not allowed in filter."));
        endpoints.findUsers("id pr", "ascending", 0, 100, false);
    }

    @Test
    public void testBadFilter5() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Invalid operator."));
        endpoints.findUsers("id gt \"foo\"", "ascending", 0, 100, false);
    }
    @Test
    public void testBadFilter6() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Invalid operator."));
        endpoints.findUsers("id gt \"foo\"", "ascending", 0, 100, false);
    }
    @Test
    public void testBadFilter7() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Invalid operator."));
        endpoints.findUsers("id lt \"foo\"", "ascending", 0, 100, false);
    }
    @Test
    public void testBadFilter8() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Invalid operator."));
        endpoints.findUsers("id le \"foo\"", "ascending", 0, 100, false);
    }

    @Test
    public void testBadFilter9() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Invalid filter"));
        endpoints.findUsers("origin eq \"uaa\"", "ascending", 0, 100, false);
    }

    @Test
    public void testDisabled() {
        endpoints.setEnabled(false);
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Illegal operation."));
        endpoints.findUsers("id eq \"foo\"", "ascending", 0, 100, false);
    }

    @Test
    public void noActiveIdps_ReturnsEmptyResources() throws Exception {
        when(provisioning.retrieveActive(anyString())).thenReturn(Collections.emptyList());
        SearchResults<?> searchResults = endpoints.findUsers("username eq \"foo\"", "ascending", 0, 100, false);
        assertTrue(searchResults.getResources().isEmpty());
    }
}
