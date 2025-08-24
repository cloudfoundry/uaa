package org.cloudfoundry.identity.uaa.oauth.provider.vote;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class ScopeVoterTests {

    private final ScopeVoter voter = new ScopeVoter();

    @Test
    void abstainIfNotOAuth2() {
        Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
        assertThat(voter.vote(clientAuthentication, null,
                Collections.singleton(new SecurityConfig("SCOPE_READ")))).isEqualTo(AccessDecisionVoter.ACCESS_ABSTAIN);
    }

    @Test
    void denyIfOAuth2AndExplictlyDenied() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertThat(voter.vote(oAuth2Authentication, null,
                Collections.singleton(new SecurityConfig("DENY_OAUTH")))).isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
    }

    @Test
    void accessGrantedIfScopesPresent() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertThat(voter.vote(oAuth2Authentication, null,
                Collections.singleton(new SecurityConfig("SCOPE_READ")))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
    }

    @Test
    void accessGrantedIfScopesPresentWithPrefix() {
        voter.setScopePrefix("scope=");
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        assertThat(voter.vote(oAuth2Authentication, null,
                Collections.singleton(new SecurityConfig("scope=read")))).isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
    }

    @Test
    void accessDeniedIfWrongScopesPresent() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        voter.setThrowException(false);
        assertThat(voter.vote(oAuth2Authentication, null,
                Collections.singleton(new SecurityConfig("SCOPE_WRITE")))).isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
    }

    @Test
    void exceptionThrownIfWrongScopesPresent() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, null);
        voter.setDenyAccess("DENY_OAUTH");
        assertThat(voter.supports(ScopeVoter.class)).isTrue();
        Set<ConfigAttribute> scopeWrite = Collections.singleton(new SecurityConfig("SCOPE_WRITE"));
        assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> voter.vote(oAuth2Authentication, null, scopeWrite));
    }
}
