package org.cloudfoundry.identity.uaa.oauth.provider;

import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.implicit.ImplicitTokenRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2RequestTests {

    private OAuth2Request oAuth2Request;

    @BeforeEach
    void setUp() {

        oAuth2Request = new OAuth2Request(Map.of("client_id", "id"), "id", Collections.emptyList(), true, Set.of("client"),
                Set.of(), null, null, Map.of("extra", "param"));
    }

    @Test
    void getRedirectUri() {
        assertThat(oAuth2Request.getRedirectUri()).isNull();
    }

    @Test
    void getResponseTypes() {
        assertThat(oAuth2Request.getResponseTypes()).isEqualTo(Set.of());
    }

    @Test
    void getAuthorities() {
        assertThat(oAuth2Request.getAuthorities()).isEqualTo(Set.of());
    }

    @Test
    void isApproved() {
        assertThat(oAuth2Request.isApproved()).isTrue();
    }

    @Test
    void getResourceIds() {
        assertThat(oAuth2Request.getResourceIds()).isEqualTo(Set.of());
    }

    @Test
    void getExtensions() {
        assertThat(oAuth2Request.getExtensions()).isEqualTo(Map.of("extra", "param"));
    }

    @Test
    void createOAuth2Request() {
        OAuth2Request copyOf = new OAuth2Request(oAuth2Request);
        assertThat(copyOf).isEqualTo(oAuth2Request);
        OAuth2Request fromClient = new OAuth2Request("id");
        assertThat(fromClient).isNotEqualTo(oAuth2Request);
        assertThat(new OAuth2Request()).isNotEqualTo(oAuth2Request);
        OAuth2Request paramCopy = oAuth2Request.createOAuth2Request(Map.of("extra", "param"));
        assertThat(paramCopy).isNotEqualTo(oAuth2Request);
    }

    @Test
    void narrowScope() {
        OAuth2Request narrow = oAuth2Request.narrowScope(Set.of("scope1", "scope2"));
        assertThat(narrow.getScope()).isEqualTo(Set.of("scope1", "scope2"));
    }

    @Test
    void refresh() {
        OAuth2Request request = oAuth2Request.refresh(new ImplicitTokenRequest(mock(TokenRequest.class), mock(OAuth2Request.class)));
        assertThat(request.getScope()).isEqualTo(Set.of("client"));
        assertThat(request).isEqualTo(oAuth2Request);
        assertThat(request.getRefreshTokenRequest()).isNotNull();
    }

    @Test
    void isRefresh() {
        OAuth2Request request = oAuth2Request.refresh(new ImplicitTokenRequest(mock(TokenRequest.class), mock(OAuth2Request.class)));
        assertThat(request.isRefresh()).isTrue();
    }

    @Test
    void getRefreshTokenRequest() {
        assertThat(oAuth2Request.getRefreshTokenRequest()).isNull();
        assertThat(oAuth2Request.refresh(new ImplicitTokenRequest(mock(TokenRequest.class), mock(OAuth2Request.class))).getRefreshTokenRequest()).isNotNull();
    }

    @Test
    void getGrantType() {
        assertThat(oAuth2Request.getGrantType()).isNull();
        oAuth2Request.setRequestParameters(Map.of(OAuth2Utils.GRANT_TYPE, "implicit"));
        assertThat(oAuth2Request.getGrantType()).isEqualTo("implicit");
        oAuth2Request.setRequestParameters(Map.of(OAuth2Utils.RESPONSE_TYPE, "token"));
        assertThat(oAuth2Request.getGrantType()).isEqualTo("implicit");
    }

    @Test
    void getRequestParameters() {
        oAuth2Request.setRequestParameters(Map.of(OAuth2Utils.RESPONSE_TYPE, "token"));
        assertThat(oAuth2Request.getRequestParameters()).containsEntry("response_type", "token");
    }

    @Test
    void equals() {
        OAuth2Request copyOf = new OAuth2Request(oAuth2Request);
        assertThat(copyOf).isEqualTo(oAuth2Request)
                .hasSameHashCodeAs(oAuth2Request);
    }
}
