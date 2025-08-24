package org.cloudfoundry.identity.uaa.oauth.provider.expression;

import org.aopalliance.intercept.MethodInvocation;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.RequestTokenFactory;
import org.junit.jupiter.api.Test;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.util.SimpleMethodInvocation;
import org.springframework.util.ReflectionUtils;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2MethodSecurityExpressionHandlerTests {

    private final OAuth2MethodSecurityExpressionHandler handler = new OAuth2MethodSecurityExpressionHandler();

    @Test
    void scopesWithOr() throws Exception {
        AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
        request.setResourceIdsAndAuthoritiesFromClientDetails(new UaaClientDetails("foo", "bar", "",
                "client_credentials", "ROLE_CLIENT"));
        request.setApproved(true);
        OAuth2Request clientAuthentication = request.createOAuth2Request();
        Authentication userAuthentication = new UsernamePasswordAuthenticationToken("user", "pass",
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(),
                "oauthClient"));
        EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression(
                "#oauth2.hasAnyScope('write') or #oauth2.isUser()");
        assertThat((Boolean) expression.getValue(context)).isTrue();
    }

    @Test
    void scopesInsufficient() {
        AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
        request.setResourceIdsAndAuthoritiesFromClientDetails(new UaaClientDetails("foo", "bar", "",
                "client_credentials", "ROLE_CLIENT"));
        OAuth2Request clientAuthentication = request.createOAuth2Request();
        Authentication userAuthentication = new UsernamePasswordAuthenticationToken("user", "pass",
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(),
                "oauthClient"));
        EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression("#oauth2.hasAnyScope('write')");
        assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() ->
                expression.getValue(context));
    }

    @Test
    void oauthClient() throws Exception {
        AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
        request.setResourceIdsAndAuthoritiesFromClientDetails(new UaaClientDetails("foo", "", "",
                "client_credentials", "ROLE_CLIENT"));
        Authentication userAuthentication = null;

        OAuth2Request clientAuthentication = RequestTokenFactory
                .createOAuth2Request(request.getRequestParameters(), request.getClientId(), request.getAuthorities(),
                        request.isApproved(), request.getScope(), request.getResourceIds(), request.getRedirectUri(),
                        request.getResponseTypes(), request.getExtensions());

        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(),
                "oauthClient"));
        EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
        Expression expression = handler.getExpressionParser()
                .parseExpression("#oauth2.clientHasAnyRole('ROLE_CLIENT')");
        assertThat((Boolean) expression.getValue(context)).isTrue();
    }

    @Test
    void scopes() throws Exception {

        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false,
                Collections.singleton("read"));

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(),
                "oauthClient"));
        EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression("#oauth2.hasAnyScope('read','write')");
        assertThat((Boolean) expression.getValue(context)).isTrue();
    }

    @Test
    void scopesRegex() throws Exception {

        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false,
                Collections.singleton("ns_admin:read"));

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(),
                "oauthClient"));
        EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression(
                "#oauth2.hasScopeMatching('.*_admin:read')");
        assertThat((Boolean) expression.getValue(context)).isTrue();
        expression = handler.getExpressionParser().parseExpression(
                "#oauth2.hasAnyScopeMatching('.*_admin:write','.*_admin:read')");
        assertThat((Boolean) expression.getValue(context)).isTrue();
    }

    @Test
    void scopesRegexThrowsException() {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false,
                Collections.singleton("ns_admin:read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(),
                "oauthClient"));
        EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression(
                "#oauth2.hasScopeMatching('.*_admin:write')");
        assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() ->
                assertThat((Boolean) expression.getValue(context)).isFalse());
    }

    @Test
    void nonOauthClient() throws Exception {
        Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(),
                "nonOauthClient"));
        EvaluationContext context = handler.createEvaluationContext(clientAuthentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression("#oauth2.clientHasAnyRole()");
        assertThat((Boolean) expression.getValue(context)).isFalse();
    }

    @Test
    void standardSecurityRoot() throws Exception {
        Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar", null);
        assertThat(clientAuthentication.isAuthenticated()).isTrue();
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(),
                "standardSecurityRoot"));
        EvaluationContext context = handler.createEvaluationContext(clientAuthentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression("isAuthenticated()");
        assertThat((Boolean) expression.getValue(context)).isTrue();
    }

    @Test
    void reEvaluationWithDifferentRoot() throws Exception {
        Expression expression = handler.getExpressionParser().parseExpression("#oauth2.isClient()");
        MethodInvocation invocation = new SimpleMethodInvocation(this, ReflectionUtils.findMethod(getClass(),
                "nonOauthClient"));
        Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
        EvaluationContext context = handler.createEvaluationContext(clientAuthentication, invocation);
        assertThat((Boolean) expression.getValue(context)).isFalse();

        OAuth2Request storedOAuth2Request = RequestTokenFactory.createOAuth2Request("foo", true,
                Collections.singleton("read"));

        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(storedOAuth2Request, null);
        EvaluationContext anotherContext = handler.createEvaluationContext(oAuth2Authentication, invocation);
        assertThat((Boolean) expression.getValue(anotherContext)).isTrue();
    }
}
