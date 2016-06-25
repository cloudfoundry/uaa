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
package org.cloudfoundry.identity.uaa.oauth;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.support.SimpleSessionStatus;

/**
 * @author Dave Syer
 * 
 */
public class AccessControllerTests {

    private AccessController controller = new AccessController();

    @Test
    public void testSunnyDay() throws Exception {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.setClientDetailsStore(Collections.singletonMap("client", new BaseClientDetails()));
        controller.setClientDetailsService(clientDetailsService);
        controller.setApprovalStore(mock(ApprovalStore.class));
        Authentication auth = UaaAuthenticationTestFactory.getAuthentication("foo@bar.com", "Foo Bar", "foo@bar.com");
        String result = controller.confirm(new ModelMap(), new MockHttpServletRequest(), auth,
                        new SimpleSessionStatus());
        assertEquals("access_confirmation", result);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testSchemePreserved() throws Exception {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.setClientDetailsStore(Collections.singletonMap("client", new BaseClientDetails()));
        controller.setClientDetailsService(clientDetailsService);
        controller.setApprovalStore(mock(ApprovalStore.class));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.addHeader("Host", "foo");
        ModelMap model = new ModelMap();
        model.put("authorizationRequest", new AuthorizationRequest("client", null));
        Authentication auth = UaaAuthenticationTestFactory.getAuthentication("foo@bar.com", "Foo Bar", "foo@bar.com");
        controller.confirm(model, request, auth, new SimpleSessionStatus());
        Map<String, Object> options = (Map<String, Object>) ((Map<String, Object>) model.get("options")).get("confirm");
        assertEquals("https://foo/oauth/authorize", options.get("location"));
        assertEquals("/oauth/authorize", options.get("path"));
    }

    @Test
    public void testClientDisplayName() throws Exception {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        BaseClientDetails client = new BaseClientDetails();
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, "The Client Name");
        clientDetailsService.setClientDetailsStore(Collections.singletonMap("client-id", client));
        controller.setClientDetailsService(clientDetailsService);

        controller.setApprovalStore(mock(ApprovalStore.class));

        Authentication auth = UaaAuthenticationTestFactory.getAuthentication("foo@bar.com", "Foo Bar", "foo@bar.com");

        ModelMap model = new ModelMap();
        model.put("authorizationRequest", new AuthorizationRequest("client-id", null));

        controller.confirm(model, new MockHttpServletRequest(), auth, new SimpleSessionStatus());

        assertEquals("The Client Name", model.get("client_display_name"));
    }

    @Test
    public void approvedScopes_doNotShowUpForApproval() throws Exception {
        performAutoApprovedScopeTest(Arrays.asList("resource.scope1","resource.scope2"));
    }

    @Test
    public void approvedScopes_doNotShowUpForApproval_ifAutoApprovedHasTrue() throws Exception {
        performAutoApprovedScopeTest(Arrays.asList("true"));
    }

    private void performAutoApprovedScopeTest(List<String> autoApprovedScopes) throws Exception {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        BaseClientDetails client = new BaseClientDetails();
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, "The Client Name");
        client.setAutoApproveScopes(autoApprovedScopes);
        client.setScope(Arrays.asList("resource.scope1","resource.scope2"));
        clientDetailsService.setClientDetailsStore(Collections.singletonMap("client-id", client));

        ScimGroupProvisioning provisioning = mock(JdbcScimGroupProvisioning.class);
        ScimGroup scimGroup1 = new ScimGroup("resource.scope1");
        ScimGroup scimGroup2 = new ScimGroup("resource.scope2");
        when(provisioning.query(anyString())).thenReturn(new ArrayList<>(Arrays.asList(scimGroup1))).thenReturn(new ArrayList<>(Arrays.asList(scimGroup2)));
        controller.setClientDetailsService(clientDetailsService);
        controller.setGroupProvisioning(provisioning);

        controller.setApprovalStore(mock(ApprovalStore.class));

        Authentication auth = UaaAuthenticationTestFactory.getAuthentication("foo@bar.com", "Foo Bar", "foo@bar.com");

        ModelMap model = new ModelMap();
        model.put("authorizationRequest", new AuthorizationRequest("client-id", Arrays.asList("resource.scope1","resource.scope2")));

        controller.confirm(model, new MockHttpServletRequest(), auth, new SimpleSessionStatus());
        List<Map<String,String>> undecidedScopeDetails = (List<Map<String, String>>) model.get("undecided_scopes");
        assertThat(undecidedScopeDetails, not(Matchers.hasItem(hasEntry("text", "resource.scope1"))));
        assertThat(undecidedScopeDetails, not(Matchers.hasItem(hasEntry("text", "resource.scope2"))));
    }
}
