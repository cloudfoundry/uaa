package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.advice.HttpMethodNotSupportedAdvice;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.TokenEndpoint;
import org.cloudfoundry.identity.uaa.oauth.tls.RawPeerCertificateCaptureFilter;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.springframework.stereotype.Controller;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.springframework.util.StringUtils.hasText;

@Controller
@RequestMapping(value = {"/oauth/token", "/oauth/mtls/token"}) //used simply because TokenEndpoint wont match /oauth/token/alias/saml-entity-id
public class UaaTokenEndpoint extends TokenEndpoint {

    private final boolean allowQueryString;

    public UaaTokenEndpoint(
            final @Qualifier("authorizationRequestManager") OAuth2RequestFactory oAuth2RequestFactory,
            final @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientDetailsService,
            final @Qualifier("oauth2RequestValidator") OAuth2RequestValidator oAuth2RequestValidator,
            final @Qualifier("oauth2TokenGranter") TokenGranter tokenGranter,
            final @Qualifier("allowQueryStringForTokens") Boolean allowQueryStringForTokens
    ) {
        this.setOAuth2RequestFactory(oAuth2RequestFactory);
        this.setClientDetailsService(clientDetailsService);
        this.setOAuth2RequestValidator(oAuth2RequestValidator);
        this.setTokenGranter(tokenGranter);

        this.allowQueryString = Boolean.TRUE.equals(Optional
                .ofNullable(allowQueryStringForTokens)
                .orElse(Boolean.TRUE));

        if (allowQueryString) {
            super.setAllowedRequestMethods(new HashSet<>(Arrays.asList(HttpMethod.GET, HttpMethod.POST)));
        } else {
            super.setAllowedRequestMethods(Collections.singleton(HttpMethod.POST));
        }
    }

    @GetMapping("**")
    public ResponseEntity<OAuth2AccessToken> doDelegateGet(Principal principal,
            @RequestParam Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
        rejectNonWorkloadGrantAtMtlsEndpoint(currentRequest(), parameters);
        return getAccessToken(principal, parameters);
    }

    @PostMapping("**")
    public ResponseEntity<OAuth2AccessToken> doDelegatePost(Principal principal,
            @RequestParam Map<String, String> parameters,
            HttpServletRequest request) throws HttpRequestMethodNotSupportedException {
        if (hasText(request.getQueryString()) && !this.allowQueryString) {
            logger.debug("Call to /oauth/token contains a query string. Aborting.");
            throw new HttpRequestMethodNotSupportedException("POST");
        }
        rejectNonWorkloadGrantAtMtlsEndpoint(request, parameters);
        return postAccessToken(principal, parameters);
    }

    /**
     * The mTLS token endpoint exists to exchange a workload's X.509 identity for a token about that
     * workload, so it issues {@code client_credentials} tokens only.
     *
     * <p>Every other grant was reachable here: the chain installs
     * {@code BackwardsCompatibleTokenEndpointAuthenticationFilter} exactly as {@code /oauth/token}
     * does. A certificate-authenticated client whose {@code authorized_grant_types} include
     * {@code password} could therefore exchange a username and password for a user token at this
     * endpoint, and {@code MtlsClaimsEnhancer} would stamp it with {@code cnf.x5t#S256} -- the RFC 8705
     * section 3 confirmation claim, which tells a resource server "the presenter holds this
     * certificate". The result was a single token asserting two unrelated identities: the app
     * instance's (via {@code cnf} and the certificate-derived claims) and the user's (via
     * {@code user_id}/{@code user_name}/{@code email}), with nothing marking which claim came from
     * which credential. The refresh token it returned was usable here too.
     *
     * <p>Rejected as {@code invalid_grant} rather than silently stripping {@code cnf}, so an operator
     * who configured a grant that cannot work here is told, instead of receiving a token that quietly
     * means less than it appears to.
     */
    private static void rejectNonWorkloadGrantAtMtlsEndpoint(
            HttpServletRequest request, Map<String, String> parameters) {
        if (request == null || !RawPeerCertificateCaptureFilter.isMtlsTokenPath(request.getServletPath())) {
            return;
        }
        String grantType = parameters == null ? null : parameters.get("grant_type");
        if (!GRANT_TYPE_CLIENT_CREDENTIALS.equals(grantType)) {
            // Deliberately does not echo the submitted grant_type back into the response.
            throw new InvalidGrantException(
                    "the mTLS token endpoint only issues client_credentials tokens");
        }
    }

    /**
     * The servlet request for the call in progress, or {@code null} when there is no request context
     * -- which is the case when {@code doDelegateGet} is invoked directly from a unit test. Used
     * instead of adding an {@code HttpServletRequest} parameter to {@code doDelegateGet}, whose
     * signature existing tests call directly.
     */
    private static HttpServletRequest currentRequest() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        return attributes instanceof ServletRequestAttributes servletAttributes
                ? servletAttributes.getRequest()
                : null;
    }

    @RequestMapping(value = "**")
    public void methodsNotAllowed(HttpServletRequest request) throws HttpRequestMethodNotSupportedException {
        throw new HttpRequestMethodNotSupportedException(request.getMethod());
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    @Override
    public ResponseEntity<OAuth2Exception> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException e) throws Exception {
        return new HttpMethodNotSupportedAdvice().handleMethodNotSupportedException(e);
    }

    @ExceptionHandler(Exception.class)
    @Override
    public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {
        logger.error("Handling error: " + e.getClass().getSimpleName() + ", " + e.getMessage(), e);
        return getExceptionTranslator().translate(e);
    }

    /**
     * This is a NOOP
     * This class will control which request methods are allowed,
     * based on allowQueryStringForTokens
     */
    @Override
    public void setAllowedRequestMethods(Set<HttpMethod> allowedRequestMethods) {
    }
}
