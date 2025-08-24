package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.JdbcAuditService;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
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
    void getOrigin() {
        UaaOauth2Authentication authentication = mock(UaaOauth2Authentication.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(authentication.getName()).thenReturn("marissa");
        when(authentication.getDetails()).thenReturn(Map.of("misc", "somedetails", "remoteAddress", "external"));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String originString = event.getOrigin(authentication);
        assertThat(originString).contains("marissa")
                .contains("client=null")
                .contains("misc=somedetails")
                .contains("remoteAddress=external")
                .contains("details=({");
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
                .doesNotContain("{");
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
