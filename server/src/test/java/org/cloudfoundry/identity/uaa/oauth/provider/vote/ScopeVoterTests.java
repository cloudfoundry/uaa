package org.cloudfoundry.identity.uaa.oauth.provider.vote;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.junit.Test;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class ScopeVoterTests {

	private ScopeVoter voter = new ScopeVoter();

	@Test
	public void testAbstainIfNotOAuth2() throws Exception {
		Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
		assertEquals(
				AccessDecisionVoter.ACCESS_ABSTAIN,
				voter.vote(clientAuthentication, null,
						Collections.<ConfigAttribute> singleton(new SecurityConfig("SCOPE_READ"))));
	}

	@Test
	public void testDenyIfOAuth2AndExplictlyDenied() throws Exception {

		OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertEquals(
				AccessDecisionVoter.ACCESS_DENIED,
				voter.vote(oAuth2Authentication, null,
						Collections.<ConfigAttribute> singleton(new SecurityConfig("DENY_OAUTH"))));
	}

	@Test
	public void testAccessGrantedIfScopesPresent() throws Exception {
		OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertEquals(
				AccessDecisionVoter.ACCESS_GRANTED,
				voter.vote(oAuth2Authentication, null,
						Collections.<ConfigAttribute> singleton(new SecurityConfig("SCOPE_READ"))));
	}

	@Test
	public void testAccessGrantedIfScopesPresentWithPrefix() throws Exception {
		voter.setScopePrefix("scope=");
		OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		assertEquals(
				AccessDecisionVoter.ACCESS_GRANTED,
				voter.vote(oAuth2Authentication, null,
						Collections.<ConfigAttribute> singleton(new SecurityConfig("scope=read"))));
	}

	@Test
	public void testAccessDeniedIfWrongScopesPresent() throws Exception {
		OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		voter.setThrowException(false);
		assertEquals(
				AccessDecisionVoter.ACCESS_DENIED,
				voter.vote(oAuth2Authentication, null,
						Collections.<ConfigAttribute> singleton(new SecurityConfig("SCOPE_WRITE"))));
	}

	@Test(expected = AccessDeniedException.class)
	public void testExceptionThrownIfWrongScopesPresent() throws Exception {
		OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false, Collections.singleton("read"));
		Authentication userAuthentication = null;
		OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
		voter.setDenyAccess("DENY_OAUTH");
		assertTrue(voter.supports(ScopeVoter.class));
		assertEquals(
				AccessDecisionVoter.ACCESS_DENIED,
				voter.vote(oAuth2Authentication, null,
						Collections.<ConfigAttribute> singleton(new SecurityConfig("SCOPE_WRITE"))));
	}
}
