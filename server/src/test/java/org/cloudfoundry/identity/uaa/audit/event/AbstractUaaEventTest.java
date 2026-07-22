package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.JdbcAuditService;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.authentication.OAuth2AuthenticationDetails;
import org.cloudfoundry.identity.uaa.scim.event.GroupModifiedEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class AbstractUaaEventTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    AbstractUaaEvent event;
    UaaAuditService auditListener;

    @BeforeEach
    void setUp() {
        event = GroupModifiedEvent.groupCreated("group", "groupName", new String[0], "uaa");
        auditListener = new JdbcAuditService(jdbcTemplate);
    }

    @AfterEach
    void cleanUp() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void process() {
        event.process(auditListener);
        assertThat(auditListener).isNotNull();
    }

    @Test
    void createAuditRecord() {
        assertThat(event.createAuditRecord("me", AuditEventType.GroupModifiedEvent, "notuaa")).isNotNull();
    }

    @Test
    void getAuthentication() {
        assertThat(event.getAuthentication()).isNotNull();
    }

    @Test
    void getContextAuthentication() {
        Authentication authentication = AbstractUaaEvent.getContextAuthentication();
        assertThat(authentication).isNotNull();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String originString = event.getOrigin(authentication);
        assertThat(originString).isEqualTo("caller=null");
    }

    @Test
    void getOrigin_whenMapDetailsHasNoKnownKeys_doesNotLeakMapContents() {
        UaaOauth2Authentication authentication = mock(UaaOauth2Authentication.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(authentication.getName()).thenReturn("marissa");
        when(authentication.getDetails()).thenReturn(Map.of("grant_type", "password", "username", "marissa", "client_id", "clientid"));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String originString = event.getOrigin(authentication);
        assertThat(originString).contains("marissa")
                .contains("client=null")
                .doesNotContain("remoteAddress=")
                .doesNotContain("grant_type=")
                .doesNotContain("username=")
                .doesNotContain("client_id=");
    }

    @Test
    void getOrigin_whenMapDetailsContainsRemoteAddress_extractsRemoteAddress() {
        UaaOauth2Authentication authentication = mock(UaaOauth2Authentication.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(authentication.getName()).thenReturn("marissa");
        when(authentication.getDetails()).thenReturn(Map.of("grant_type", "password", "remoteAddress", "10.0.0.1"));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String originString = event.getOrigin(authentication);
        assertThat(originString).contains("marissa")
                .contains("remoteAddress=10.0.0.1")
                .doesNotContain("grant_type=");
    }

    @Test
    void getOriginNotAuthenticated() {
        assertThat(event.getOrigin(null)).isNull();
    }

    @Test
    void getOriginDetailsParsed() {
        UaaOauth2Authentication authentication = mock(UaaOauth2Authentication.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(authentication.getName()).thenReturn("marissa");
        when(authentication.getDetails()).thenReturn("{\"misc\":\"somedetails\",\"remoteAddress\":\"external\"}");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String originString = event.getOrigin(authentication);
        assertThat(originString).contains("marissa")
                .contains("client=null")
                .doesNotContain("misc=somedetails")
                .contains("remoteAddress=external")
                .contains("type=String")
                .doesNotContain("{");
    }

    @Test
    void getOrigin_whenOAuth2AuthenticationWithUser_emitsClientAndUser() {
        OAuth2Authentication authentication = mock(OAuth2Authentication.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(oAuth2Request.getClientId()).thenReturn("clientid");
        when(authentication.isClientOnly()).thenReturn(false);
        when(authentication.getName()).thenReturn("marissa");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String originString = event.getOrigin(authentication);
        assertThat(originString).contains("client=clientid")
                .contains("user=marissa");
    }

    @Test
    void getOrigin_whenStringDetailsIsNotJson_omitsRemoteAddress() {
        UaaOauth2Authentication authentication = mock(UaaOauth2Authentication.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(authentication.getName()).thenReturn("marissa");
        when(authentication.getDetails()).thenReturn("session-id-abc");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String originString = event.getOrigin(authentication);
        assertThat(originString).contains("marissa")
                .contains("type=String")
                .doesNotContain("remoteAddress=");
    }

    @Test
    void getOrigin_whenJsonDetailsMissingRemoteAddress_omitsRemoteAddress() {
        UaaOauth2Authentication authentication = mock(UaaOauth2Authentication.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(authentication.getName()).thenReturn("marissa");
        when(authentication.getDetails()).thenReturn("{\"remoteAddress\":null,\"sessionId\":\"abc\"}");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String originString = event.getOrigin(authentication);
        assertThat(originString).contains("marissa")
                .contains("type=String")
                .doesNotContain("remoteAddress=");
    }

    @Test
    void getOrigin_whenUaaAuthenticationDetails_extractsRemoteAddressFromAccessor() {
        UaaOauth2Authentication authentication = mock(UaaOauth2Authentication.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(authentication.getName()).thenReturn("marissa");
        UaaAuthenticationDetails uaaDetails = mock(UaaAuthenticationDetails.class);
        when(uaaDetails.getOrigin()).thenReturn("10.0.0.1");
        when(authentication.getDetails()).thenReturn(uaaDetails);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String originString = event.getOrigin(authentication);
        assertThat(originString).contains("details=(remoteAddress=10.0.0.1, type=UaaAuthenticationDetails");
    }

    @Test
    void getOrigin_whenOAuth2AuthenticationDetails_extractsRemoteAddressFromAccessor() {
        OAuth2Authentication authentication = mock(OAuth2Authentication.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(oAuth2Request.getClientId()).thenReturn("clientid");
        when(authentication.isClientOnly()).thenReturn(true);
        OAuth2AuthenticationDetails oauthDetails = mock(OAuth2AuthenticationDetails.class);
        when(oauthDetails.getRemoteAddress()).thenReturn("172.18.0.1");
        when(authentication.getDetails()).thenReturn(oauthDetails);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String originString = event.getOrigin(authentication);
        assertThat(originString).contains("client=clientid")
                .contains("details=(remoteAddress=172.18.0.1, type=OAuth2AuthenticationDetails");
    }

    @Test
    void getAuthenticationJsonWebTokenValue() {
        String originTokenString = event.getOrigin(mockAuthenticationWithToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtYXJpc3NhIiwiaXNzIjoidWFhIn0.omitted"));
        assertThat(originTokenString).contains("client=clientid")
                .contains("iss=uaa")
                .contains("sub=marissa");
    }

    @Test
    void getAuthenticationOpaqueTokenValue() {
        String originTokenString = event.getOrigin(mockAuthenticationWithToken("any-value"));
        assertThat(originTokenString).contains("client=clientid")
                .contains("opaque-token=present")
                .doesNotContain("any-value");
    }

    @Test
    void getAuthenticationTokenValueInvalid() {
        String originTokenString = event.getOrigin(mockAuthenticationWithToken("fake.token.value"));
        assertThat(originTokenString).contains("client=clientid")
                .contains("<token extraction failed>")
                .doesNotContain("fake")
                .doesNotContain("value");
    }

    private Authentication mockAuthenticationWithToken(String token) {
        OAuth2Authentication authentication = mock(OAuth2Authentication.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        OAuth2AuthenticationDetails auth2AuthenticationDetails = mock(OAuth2AuthenticationDetails.class);
        when(authentication.getDetails()).thenReturn(auth2AuthenticationDetails);
        when(authentication.isClientOnly()).thenReturn(true);
        when(auth2AuthenticationDetails.getTokenValue()).thenReturn(token);
        when(oAuth2Request.getClientId()).thenReturn("clientid");
        return authentication;
    }

    @Test
    void getIdentityZoneId() {
        assertThat(event.getIdentityZoneId()).isEqualTo("uaa");
    }
}
