package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.InMemoryMultitenantClientServices;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.support.SimpleSessionStatus;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AccessControllerTests {

    private AccessController controller = new AccessController();

    @Test
    public void testSunnyDay() throws Exception {
        InMemoryMultitenantClientServices clientDetailsService = new InMemoryMultitenantClientServices(null);
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap("client", new BaseClientDetails()));
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
        InMemoryMultitenantClientServices clientDetailsService = new InMemoryMultitenantClientServices(null);
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap("client", new BaseClientDetails()));
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
        InMemoryMultitenantClientServices clientDetailsService = new InMemoryMultitenantClientServices(null);
        BaseClientDetails client = new BaseClientDetails();
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, "The Client Name");
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap("client-id", client));
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
        InMemoryMultitenantClientServices clientDetailsService = new InMemoryMultitenantClientServices(null);
        BaseClientDetails client = new BaseClientDetails();
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, "The Client Name");
        client.setAutoApproveScopes(autoApprovedScopes);
        client.setScope(Arrays.asList("resource.scope1","resource.scope2"));
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap("client-id", client));

        ScimGroupProvisioning provisioning = mock(JdbcScimGroupProvisioning.class);
        ScimGroup scimGroup1 = new ScimGroup("resource.scope1");
        ScimGroup scimGroup2 = new ScimGroup("resource.scope2");
        when(provisioning.query(any(), any()))
            .thenReturn(new ArrayList<>(Arrays.asList(scimGroup1)))
            .thenReturn(new ArrayList<>(Arrays.asList(scimGroup2)));
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
