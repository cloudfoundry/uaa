package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.advice.HttpMethodNotSupportedAdvice;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.TokenEndpoint;
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

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.springframework.util.StringUtils.hasText;

@Controller
@RequestMapping(value = "/oauth/token") //used simply because TokenEndpoint wont match /oauth/token/alias/saml-entity-id
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
        return postAccessToken(principal, parameters);
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
