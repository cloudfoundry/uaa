package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.InMemoryMultitenantClientServices;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.support.SimpleSessionStatus;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AccessControllerTests {

    private AccessController controller;
    private UaaClientDetails client;
    private ScimGroupProvisioning mockScimGroupProvisioning;

    @BeforeEach
    void setUp() {
        client = new UaaClientDetails();
        InMemoryMultitenantClientServices clientDetailsService = new InMemoryMultitenantClientServices(null);
        clientDetailsService.setClientDetailsStore(IdentityZoneHolder.get().getId(), Collections.singletonMap("client-id", client));

        mockScimGroupProvisioning = mock(ScimGroupProvisioning.class);
        controller = new AccessController(clientDetailsService, null, mock(ApprovalStore.class), mockScimGroupProvisioning);
    }

    @Test
    void sunnyDay() {
        Authentication auth = UaaAuthenticationTestFactory.getAuthentication("foo@bar.com", "Foo Bar", "foo@bar.com");
        String result = controller.confirm(new ModelMap(), new MockHttpServletRequest(), auth,
                new SimpleSessionStatus());
        assertThat(result).isEqualTo("access_confirmation");
    }

    @SuppressWarnings("unchecked")
    @Test
    void schemePreserved() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.addHeader("Host", "foo");
        ModelMap model = new ModelMap();
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, new AuthorizationRequest("client-id", null));
        Authentication auth = UaaAuthenticationTestFactory.getAuthentication("foo@bar.com", "Foo Bar", "foo@bar.com");
        controller.confirm(model, request, auth, new SimpleSessionStatus());
        Map<String, Object> options = (Map<String, Object>) ((Map<String, Object>) model.get("options")).get("confirm");
        assertThat(options).containsEntry("location", "https://foo/oauth/authorize")
                .containsEntry("path", "/oauth/authorize");
    }

    @Test
    void clientDisplayName() {
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, "The Client Name");


        Authentication auth = UaaAuthenticationTestFactory.getAuthentication("foo@bar.com", "Foo Bar", "foo@bar.com");

        ModelMap model = new ModelMap();
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, new AuthorizationRequest("client-id", null));

        controller.confirm(model, new MockHttpServletRequest(), auth, new SimpleSessionStatus());

        assertThat(model).containsEntry("client_display_name", "The Client Name");
    }

    @Test
    void approvedScopes_doNotShowUpForApproval() throws Exception {
        performAutoApprovedScopeTest(Arrays.asList("resource.scope1", "resource.scope2"));
    }

    @Test
    void approvedScopes_doNotShowUpForApproval_ifAutoApprovedHasTrue() throws Exception {
        performAutoApprovedScopeTest(Collections.singletonList("true"));
    }

    private void performAutoApprovedScopeTest(List<String> autoApprovedScopes) {
        client.addAdditionalInformation(ClientConstants.CLIENT_NAME, "The Client Name");
        client.setAutoApproveScopes(autoApprovedScopes);
        client.setScope(Arrays.asList("resource.scope1", "resource.scope2"));

        ScimGroup scimGroup1 = new ScimGroup("resource.scope1");
        ScimGroup scimGroup2 = new ScimGroup("resource.scope2");
        when(mockScimGroupProvisioning.query(any(), any()))
                .thenReturn(new ArrayList<>(Collections.singletonList(scimGroup1)))
                .thenReturn(new ArrayList<>(Collections.singletonList(scimGroup2)));

        Authentication auth = UaaAuthenticationTestFactory.getAuthentication("foo@bar.com", "Foo Bar", "foo@bar.com");

        ModelMap model = new ModelMap();
        model.put(UaaAuthorizationEndpoint.AUTHORIZATION_REQUEST, new AuthorizationRequest("client-id", Arrays.asList("resource.scope1", "resource.scope2")));

        controller.confirm(model, new MockHttpServletRequest(), auth, new SimpleSessionStatus());
        List<Map<String, String>> undecidedScopeDetails = (List<Map<String, String>>) model.get("undecided_scopes");
        assertThat(undecidedScopeDetails).noneSatisfy(e -> assertThat(e).containsEntry("text", "resource.scope1"))
                .noneSatisfy(e -> assertThat(e).containsEntry("text", "resource.scope2"));
    }
}
