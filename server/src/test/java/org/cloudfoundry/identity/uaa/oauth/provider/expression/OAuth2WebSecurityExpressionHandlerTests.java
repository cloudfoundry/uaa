package org.cloudfoundry.identity.uaa.oauth.provider.expression;

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
import org.springframework.security.web.FilterInvocation;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2WebSecurityExpressionHandlerTests {

    private final OAuth2WebSecurityExpressionHandler handler = new OAuth2WebSecurityExpressionHandler();

    @Test
    void scopesWithOr() throws Exception {
        AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
        request.setResourceIdsAndAuthoritiesFromClientDetails(new UaaClientDetails("foo", "bar", "",
                "client_credentials", "ROLE_USER"));
        request.setApproved(true);
        OAuth2Request clientAuthentication = request.createOAuth2Request();
        Authentication userAuthentication = new UsernamePasswordAuthenticationToken("user", "pass",
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        FilterInvocation invocation = new FilterInvocation("/foo", "GET");
        EvaluationContext context = handler.createEvaluationContext(oAuth2Authentication, invocation);
        Expression expression = handler.getExpressionParser().parseExpression(
                "#oauth2.hasAnyScope('write') or #oauth2.isUser()");
        assertThat((Boolean) expression.getValue(context)).isTrue();
    }

    @Test
    void oauthClient() throws Exception {
        AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
        request.setResourceIdsAndAuthoritiesFromClientDetails(new UaaClientDetails("foo", "", "",
                "client_credentials", "ROLE_CLIENT"));

        OAuth2Request clientAuthentication = RequestTokenFactory
                .createOAuth2Request(request.getRequestParameters(), request.getClientId(), request.getAuthorities(),
                        request.isApproved(), request.getScope(), request.getResourceIds(), request.getRedirectUri(),
                        request.getResponseTypes(), request.getExtensions());

        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        FilterInvocation invocation = new FilterInvocation("/foo", "GET");
        Expression expression = handler.getExpressionParser()
                .parseExpression("#oauth2.clientHasAnyRole('ROLE_CLIENT')");
        assertThat((Boolean) expression.getValue(handler.createEvaluationContext(oAuth2Authentication, invocation))).isTrue();
    }

    @Test
    void scopes() throws Exception {
        OAuth2Request clientAuthentication = RequestTokenFactory.createOAuth2Request("foo", false,
                Collections.singleton("read"));
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        FilterInvocation invocation = new FilterInvocation("/foo", "GET");
        Expression expression = handler.getExpressionParser().parseExpression("#oauth2.hasAnyScope('read')");
        assertThat((Boolean) expression.getValue(handler.createEvaluationContext(oAuth2Authentication, invocation))).isTrue();
    }

    @Test
    void insufficientScope() {
        AuthorizationRequest request = new AuthorizationRequest("foo", Collections.singleton("read"));
        request.setResourceIdsAndAuthoritiesFromClientDetails(new UaaClientDetails("foo", "bar", "",
                "client_credentials", "ROLE_USER"));
        OAuth2Request clientAuthentication = request.createOAuth2Request();
        Authentication userAuthentication = null;
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(clientAuthentication, userAuthentication);
        OAuth2SecurityExpressionMethods root = new OAuth2SecurityExpressionMethods(oAuth2Authentication);
        boolean hasAnyScope = root.hasAnyScope("foo");
        assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() ->
                root.throwOnError(hasAnyScope));
    }

    @Test
    void nonOauthClient() throws Exception {
        Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar");
        FilterInvocation invocation = new FilterInvocation("/foo", "GET");
        Expression expression = handler.getExpressionParser().parseExpression("#oauth2.clientHasAnyRole()");
        assertThat((Boolean) expression.getValue(handler.createEvaluationContext(clientAuthentication, invocation))).isFalse();
    }

    @Test
    void standardSecurityRoot() throws Exception {
        Authentication clientAuthentication = new UsernamePasswordAuthenticationToken("foo", "bar", null);
        assertThat(clientAuthentication.isAuthenticated()).isTrue();
        FilterInvocation invocation = new FilterInvocation("/foo", "GET");
        Expression expression = handler.getExpressionParser().parseExpression("isAuthenticated()");
        assertThat((Boolean) expression.getValue(handler.createEvaluationContext(clientAuthentication, invocation))).isTrue();
    }

}
