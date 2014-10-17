/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.cloudfoundry.identity.uaa.authorization.ExternalGroupMappingAuthorizationManager;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.security.StubSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 * 
 */

@ContextConfiguration(locations = { "classpath:spring/env.xml", "classpath:spring/data-source.xml" })
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = { "", "test,postgresql", "hsqldb", "test,mysql",
                "test,oracle" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class UaaAuthorizationRequestManagerTests {

    private UaaAuthorizationRequestManager factory;

    private ClientDetailsService clientDetailsService = Mockito.mock(ClientDetailsService.class);

    private Map<String, String> parameters = new HashMap<String, String>();

    private BaseClientDetails client = new BaseClientDetails();

    @Before
    public void init() {
        parameters.put("client_id", "foo");
        factory = new UaaAuthorizationRequestManager(clientDetailsService);
        factory.setSecurityContextAccessor(new StubSecurityContextAccessor());
        Mockito.when(clientDetailsService.loadClientByClientId("foo")).thenReturn(client);
    }

    @Test
    public void testTokenRequestIncludesResourceIds() {
        SecurityContextAccessor securityContextAccessor = new StubSecurityContextAccessor() {
            @Override
            public boolean isUser() {
                return false;
            }

            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return AuthorityUtils.commaSeparatedStringToAuthorityList("aud1.test aud2.test");
            }
        };
        parameters.put("scope", "aud1.test aud2.test");
        parameters.put("client_id", client.getClientId());
        parameters.put(OAuth2Utils.GRANT_TYPE, "client_credentials");
        factory.setDefaultScopes(Arrays.asList("aud1.test"));
        factory.setSecurityContextAccessor(securityContextAccessor);
        client.setScope(StringUtils.commaDelimitedListToSet("aud1.test,aud2.test"));
        OAuth2Request request = factory.createTokenRequest(parameters, client).createOAuth2Request(client);
        assertEquals(StringUtils.commaDelimitedListToSet("aud1.test,aud2.test"), new TreeSet<>(request.getScope()));
        assertEquals(StringUtils.commaDelimitedListToSet("aud1,aud2"), new TreeSet<>(request.getResourceIds()));
    }

    @Test
    public void testFactoryProducesSomething() {
        assertNotNull(factory.createAuthorizationRequest(parameters));
    }

    @Test
    public void testScopeDefaultsToAuthoritiesForClientCredentials() {
        client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz"));
        parameters.put("grant_type", "client_credentials");
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet("foo.bar,spam.baz"), request.getScope());
    }

    @Test
    public void testScopeIncludesAuthoritiesForUser() {
        SecurityContextAccessor securityContextAccessor = new StubSecurityContextAccessor() {
            @Override
            public boolean isUser() {
                return true;
            }

            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz");
            }
        };
        factory.setSecurityContextAccessor(securityContextAccessor);
        client.setScope(StringUtils.commaDelimitedListToSet("one,two,foo.bar"));
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet("foo.bar"), new TreeSet<String>(request.getScope()));
        factory.validateParameters(request.getRequestParameters(), client);
    }

    @Test
    public void testWildcardScopesIncludesAuthoritiesForUser() {
        SecurityContextAccessor securityContextAccessor = new StubSecurityContextAccessor() {
            @Override
            public boolean isUser() {
                return true;
            }

            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return AuthorityUtils.commaSeparatedStringToAuthorityList(
                    "space.1.developer,space.2.developer,space.1.admin"
                );
            }
        };
        factory.setSecurityContextAccessor(securityContextAccessor);
        client.setScope(StringUtils.commaDelimitedListToSet("space.*.developer"));
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet("space.1.developer,space.2.developer"), new TreeSet<String>(request.getScope()));
        factory.validateParameters(request.getRequestParameters(), client);
    }

    @Test
    public void testOpenidScopeIncludeIsAResourceId() {
        SecurityContextAccessor securityContextAccessor = new StubSecurityContextAccessor() {
            @Override
            public boolean isUser() {
                return true;
            }

            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz");
            }
        };
        parameters.put("scope", "openid foo.bar");
        factory.setDefaultScopes(Arrays.asList("openid"));
        factory.setSecurityContextAccessor(securityContextAccessor);
        client.setScope(StringUtils.commaDelimitedListToSet("openid,foo.bar"));
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet("openid,foo.bar"), new TreeSet<String>(request.getScope()));
        assertEquals(StringUtils.commaDelimitedListToSet("openid,foo"), new TreeSet<String>(request.getResourceIds()));
    }

    @Test
    public void testEmptyScopeOkForClientWithNoScopes() {
        SecurityContextAccessor securityContextAccessor = new StubSecurityContextAccessor() {
            @Override
            public boolean isUser() {
                return true;
            }

            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz");
            }
        };
        factory.setSecurityContextAccessor(securityContextAccessor);
        client.setScope(StringUtils.commaDelimitedListToSet("")); // empty
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet(""), new TreeSet<String>(request.getScope()));
    }

    @Test(expected = InvalidScopeException.class)
    public void testEmptyScopeFailsClientWithScopes() {
        SecurityContextAccessor securityContextAccessor = new StubSecurityContextAccessor() {
            @Override
            public boolean isUser() {
                return true;
            }

            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz");
            }
        };
        factory.setSecurityContextAccessor(securityContextAccessor);
        client.setScope(StringUtils.commaDelimitedListToSet("one,two")); // not
                                                                         // empty
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet(""), new TreeSet<String>(request.getScope()));
    }

    @Test
    public void testResourecIdsExtracted() {
        client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("foo.bar,spam.baz"));
        parameters.put("grant_type", "client_credentials");
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet("foo,spam"), request.getResourceIds());
    }

    @Test
    public void testResourecIdsDoNotIncludeUaa() {
        client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("uaa.none,spam.baz"));
        parameters.put("grant_type", "client_credentials");
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet("spam"), request.getResourceIds());
    }

    @Test
    public void testResourceIdsWithCustomSeparator() {
        factory.setScopeSeparator("--");
        client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList("foo--bar,spam--baz"));
        parameters.put("grant_type", "client_credentials");
        AuthorizationRequest request = factory.createAuthorizationRequest(parameters);
        assertEquals(StringUtils.commaDelimitedListToSet("foo,spam"), request.getResourceIds());
    }

    @Test
    public void testScopesValid() throws Exception {
        parameters.put("scope","read");
        factory.validateParameters(parameters, new BaseClientDetails("foo", null, "read,write", "implicit", null));
    }

    @Test
    public void testScopesValidWithWildcard() throws Exception {
        parameters.put("scope","read write space.1.developer space.2.developer");
        factory.validateParameters(parameters, new BaseClientDetails("foo", null, "read,write,space.*.developer", "implicit", null));
    }

    @Test(expected = InvalidScopeException.class)
    public void testScopesInvValidWithWildcard() throws Exception {
        parameters.put("scope","read write space.1.developer space.2.developer space.1.admin");
        factory.validateParameters(parameters, new BaseClientDetails("foo", null, "read,write,space.*.developer", "implicit", null));
    }

    @Test(expected = InvalidScopeException.class)
    public void testScopesInvalid() throws Exception {
        parameters.put("scope", "admin");
        factory.validateParameters(parameters, new BaseClientDetails("foo", null, "read,write", "implicit", null));
    }

    @Test
    public void testWildcardIntersect1() throws Exception {
        Set<String> client = new HashSet<>(Arrays.asList("space.*.developer"));
        Set<String> requested = client;
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer","space.2.developer","space.1.admin","space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertEquals(2, result.size());
        assertTrue(result.contains("space.1.developer"));
        assertTrue(result.contains("space.2.developer"));
    }

    @Test
    public void testWildcardIntersect2() throws Exception {
        Set<String> client = new HashSet<>(Arrays.asList("space.*.developer"));
        Set<String> requested = new HashSet<>(Arrays.asList("space.1.developer"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer","space.2.developer","space.1.admin","space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertEquals(1, result.size());
        assertTrue(result.contains("space.1.developer"));
    }

    @Test
    public void testWildcardIntersect3() throws Exception {
        Set<String> client = new HashSet<>(Arrays.asList("space.*.developer"));
        Set<String> requested = new HashSet<>(Arrays.asList("space.*.admin"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer","space.2.developer","space.1.admin","space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertEquals(0, result.size());
    }

    @Test
    public void testWildcardIntersect4() throws Exception {
        Set<String> client = new HashSet<>(Arrays.asList("space.*.developer","space.*.admin"));
        Set<String> requested = new HashSet<>(Arrays.asList("space.*.admin"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer","space.2.developer","space.1.admin","space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertEquals(1, result.size());
        assertTrue(result.contains("space.1.admin"));
    }

    @Test
    public void testWildcardIntersect5() throws Exception {
        Set<String> client = new HashSet<>(Arrays.asList("space.*.developer","space.*.admin", "space.3.operator"));
        Set<String> requested = client;
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer","space.2.developer","space.1.admin","space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertEquals(4, result.size());
        assertTrue(result.contains("space.1.admin"));
        assertTrue(result.contains("space.3.operator"));
        assertTrue(result.contains("space.1.developer"));
        assertTrue(result.contains("space.2.developer"));
    }

    @Test
    public void testWildcardIntersect6() throws Exception {
        Set<String> client = new HashSet<>(Arrays.asList("space.*.developer,space.*.admin"));
        Set<String> requested = new HashSet<>(Arrays.asList("space.*.admin"));
        Set<String> user = new HashSet<>(Arrays.asList("space.1.developer","space.2.developer","space.1.admin","space.3.operator"));

        Set<String> result = factory.intersectScopes(requested, client, user);
        assertEquals(0, result.size());
    }

}
