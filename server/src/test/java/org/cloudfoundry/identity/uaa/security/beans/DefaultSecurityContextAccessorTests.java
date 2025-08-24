package org.cloudfoundry.identity.uaa.security.beans;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(PollutionPreventionExtension.class)
class DefaultSecurityContextAccessorTests {

    private DefaultSecurityContextAccessor defaultSecurityContextAccessor;

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @BeforeEach
    void setUp() {
        defaultSecurityContextAccessor = new DefaultSecurityContextAccessor();
    }

    @Test
    void clientIsNotUser() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("client", "secret", UaaAuthority.ADMIN_AUTHORITIES));

        assertThat(defaultSecurityContextAccessor.isUser()).isFalse();
    }

    @Test
    void uaaUserIsUser() {
        SecurityContextHolder.getContext().setAuthentication(
                UaaAuthenticationTestFactory.getAuthentication("1234", "user", "user@test.org"));

        assertThat(defaultSecurityContextAccessor.isUser()).isTrue();
    }

    @Test
    void adminUserIsAdmin() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("user", "password", UaaAuthority.ADMIN_AUTHORITIES));

        assertThat(defaultSecurityContextAccessor.isAdmin()).isTrue();
    }

    @Test
    void adminClientIsAdmin() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest("admin", null);
        authorizationRequest.setScope(UaaAuthority.ADMIN_AUTHORITIES.stream().map(UaaAuthority::getAuthority).toList());
        SecurityContextHolder.getContext().setAuthentication(new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null));

        assertThat(defaultSecurityContextAccessor.isAdmin()).isTrue();
    }

    @Test
    void zoneAdminUserIsAdmin() {
        UaaClientDetails client = new UaaClientDetails();
        List<SimpleGrantedAuthority> authorities = new LinkedList<>();
        authorities.add(new SimpleGrantedAuthority("zones." + IdentityZoneHolder.get().getId() + ".admin"));
        client.setAuthorities(authorities);

        UaaPrincipal principal = new UaaPrincipal("id", "username", "email", OriginKeys.UAA, null, IdentityZoneHolder.get().getId());
        UaaAuthentication userAuthentication = new UaaAuthentication(principal, authorities, new UaaAuthenticationDetails(new MockHttpServletRequest()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest("admin", UaaStringUtils.getStringsFromAuthorities(authorities));
        authorizationRequest.setResourceIdsAndAuthoritiesFromClientDetails(client);
        SecurityContextHolder.getContext().setAuthentication(new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication));

        assertThat(defaultSecurityContextAccessor.isAdmin()).isTrue();
    }

    @Test
    void zoneAdminUserIsNotAdmin_BecauseOriginIsNotUaa() {
        UaaClientDetails client = new UaaClientDetails();
        List<SimpleGrantedAuthority> authorities = new LinkedList<>();
        authorities.add(new SimpleGrantedAuthority("zones." + IdentityZoneHolder.get().getId() + ".admin"));
        client.setAuthorities(authorities);

        UaaPrincipal principal = new UaaPrincipal("id", "username", "email", OriginKeys.UAA, null, MultitenancyFixture.identityZone("test", "test").getId());
        UaaAuthentication userAuthentication = new UaaAuthentication(principal, authorities, new UaaAuthenticationDetails(new MockHttpServletRequest()));

        AuthorizationRequest authorizationRequest = new AuthorizationRequest("admin", UaaStringUtils.getStringsFromAuthorities(authorities));
        authorizationRequest.setResourceIdsAndAuthoritiesFromClientDetails(client);
        SecurityContextHolder.getContext().setAuthentication(new OAuth2Authentication(authorizationRequest.createOAuth2Request(), userAuthentication));

        assertThat(defaultSecurityContextAccessor.isAdmin()).isFalse();
    }

    @Test
    void zoneAdminClientIsAdmin() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest("admin", null);
        authorizationRequest.setScope(Collections.singletonList("zones." + IdentityZoneHolder.get().getId() + ".admin"));
        OAuth2Authentication authentication = new OAuth2Authentication(authorizationRequest.createOAuth2Request(), null);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, "eyJhbGciOiJSUzI1NiJ9.eyJqdGkiOiI2ZjIxOTFlYi1iODY2LTQxZDUtYTBjNy1kZTg0ZTE3OTQ3MjIiLCJzdWIiOiJhZG1pbiIsImF1dGhvcml0aWVzIjpbInNjaW0ucmVhZCIsInVhYS5hZG1pbiIsInpvbmVzLmU5ZmY4ZDJmLTk5ODEtNDhkNi04MmIzLWNjYTc0ZGY5YzFmZS5hZG1pbiIsInBhc3N3b3JkLndyaXRlIiwic2NpbS53cml0ZSIsImNsaWVudHMud3JpdGUiLCJjbGllbnRzLnJlYWQiLCJ6b25lcy5yZWFkIiwiY2xpZW50cy5zZWNyZXQiXSwic2NvcGUiOlsic2NpbS5yZWFkIiwidWFhLmFkbWluIiwiem9uZXMuZTlmZjhkMmYtOTk4MS00OGQ2LTgyYjMtY2NhNzRkZjljMWZlLmFkbWluIiwicGFzc3dvcmQud3JpdGUiLCJzY2ltLndyaXRlIiwiY2xpZW50cy53cml0ZSIsImNsaWVudHMucmVhZCIsInpvbmVzLnJlYWQiLCJjbGllbnRzLnNlY3JldCJdLCJjbGllbnRfaWQiOiJhZG1pbiIsImNpZCI6ImFkbWluIiwiYXpwIjoiYWRtaW4iLCJncmFudF90eXBlIjoiY2xpZW50X2NyZWRlbnRpYWxzIiwicmV2X3NpZyI6ImVjMWMzN2M0IiwiaWF0IjoxNDM2NTcwMjkzLCJleHAiOjE0MzY2MTM0OTMsImlzcyI6Imh0dHBzOi8vdWFhLmlkZW50aXR5LmNmLWFwcC5jb20vb2F1dGgvdG9rZW4iLCJ6aWQiOiJ1YWEiLCJhdWQiOlsiYWRtaW4iLCJzY2ltIiwidWFhIiwiem9uZXMuZTlmZjhkMmYtOTk4MS00OGQ2LTgyYjMtY2NhNzRkZjljMWZlIiwicGFzc3dvcmQiLCJjbGllbnRzIiwiem9uZXMiXX0.ajpOTnvAvHWPEXEZI4XXDIO_Omp03VgQ64W2bfbrGSIVB0lBujegXvXe-61bRqiKKbbkk85Z6AXUfz6aZXb2hjKPeZr8P9ydy23bSCsl9QNsM9D_h3KHzTkJ9G-34aMTpVi8hxmfr_UQ6J-37zoTTIQrk5nxIiwxc4HcKkl_p68");
        authentication.setDetails(new OAuth2AuthenticationDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        assertThat(defaultSecurityContextAccessor.isAdmin()).isTrue();
    }
}
