package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.oauth.UaaOauth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.BadClientCredentialsException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.UnsupportedGrantTypeException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server token endpoint
 */
public class TokenEndpoint extends AbstractEndpoint {

    private static final String HANDLING_ERROR = "Handling error: ";
    private OAuth2RequestValidator oAuth2RequestValidator = new UaaOauth2RequestValidator();

    private Set<HttpMethod> allowedRequestMethods = new HashSet<>(Arrays.asList(HttpMethod.POST));

    @GetMapping(value = "/oauth/token")
    public ResponseEntity<OAuth2AccessToken> getAccessToken(
            Principal principal, @RequestParam Map<String, String> parameters)
            throws HttpRequestMethodNotSupportedException {

        if (!allowedRequestMethods.contains(HttpMethod.GET)) {
            throw new HttpRequestMethodNotSupportedException("GET");
        }
        return postAccessToken(principal, parameters);
    }

    @PostMapping(value = "/oauth/token")
    public ResponseEntity<OAuth2AccessToken> postAccessToken(
            Principal principal, @RequestParam Map<String, String> parameters) {

        if (!(principal instanceof Authentication)) {
            throw new InsufficientAuthenticationException(
                    "There is no client authentication. Try adding an appropriate authentication filter.");
        }

        String clientId = getClientId(principal);
        ClientDetails authenticatedClient = getClientDetailsService().loadClientByClientId(clientId);

        TokenRequest tokenRequest = getOAuth2RequestFactory().createTokenRequest(parameters, authenticatedClient);

        // Only validate client details if a client is authenticated during this request.
        // Double check to make sure that the client ID is the same in the token request and authenticated client.
        if (StringUtils.hasText(clientId) && !clientId.equals(tokenRequest.getClientId())) {
            throw new InvalidClientException("Given client ID does not match authenticated client");
        }

        if (authenticatedClient != null) {
            oAuth2RequestValidator.validateScope(tokenRequest, authenticatedClient);
        }

        if (!StringUtils.hasText(tokenRequest.getGrantType())) {
            throw new InvalidRequestException("Missing grant type");
        }

        if ("implicit".equals(tokenRequest.getGrantType())) {
            throw new InvalidGrantException("Implicit grant type not supported from token endpoint");
        }

        if (isAuthCodeRequest(parameters) && !tokenRequest.getScope().isEmpty()) {
            // The scope was requested or determined during the authorization step
            logger.debug("Clearing scope of incoming token request");
            tokenRequest.setScope(Collections.<String>emptySet());
        } else if (isRefreshTokenRequest(parameters)) {
            if (UaaStringUtils.isNullOrEmpty(parameters.get("refresh_token"))) {
                throw new InvalidRequestException("refresh_token parameter not provided");
            }
            // A refresh token has its own default scopes, so we should ignore any added by the factory here.
            tokenRequest.setScope(OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)));
        }

        OAuth2AccessToken token = getTokenGranter().grant(tokenRequest.getGrantType(), tokenRequest);
        if (token == null) {
            throw new UnsupportedGrantTypeException("Unsupported grant type");
        }

        return getResponse(token);
    }

    /**
     * @param principal the currently authentication principal
     * @return a client id if there is one in the principal
     */
    protected String getClientId(Principal principal) {
        Authentication client = (Authentication) principal;
        if (!client.isAuthenticated()) {
            throw new InsufficientAuthenticationException("The client is not authenticated.");
        }
        String clientId = client.getName();
        if (client instanceof OAuth2Authentication oAuth2Authentication) {
            // Might be a client and user combined authentication
            clientId = oAuth2Authentication.getOAuth2Request().getClientId();
        }
        return clientId;
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<OAuth2Exception> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException e) throws Exception {
        if (logger.isInfoEnabled()) {
            logger.info(HANDLING_ERROR + e.getClass().getSimpleName() + ", " + e.getMessage());
        }
        return getExceptionTranslator().translate(e);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<OAuth2Exception> handleException(Exception e) throws Exception {
        if (logger.isErrorEnabled()) {
            logger.error(HANDLING_ERROR + e.getClass().getSimpleName() + ", " + e.getMessage(), e);
        }
        return getExceptionTranslator().translate(e);
    }

    @ExceptionHandler(ClientRegistrationException.class)
    public ResponseEntity<OAuth2Exception> handleClientRegistrationException(Exception e) throws Exception {
        if (logger.isWarnEnabled()) {
            logger.warn(HANDLING_ERROR + e.getClass().getSimpleName() + ", " + e.getMessage());
        }
        return getExceptionTranslator().translate(new BadClientCredentialsException());
    }

    @ExceptionHandler(OAuth2Exception.class)
    public ResponseEntity<OAuth2Exception> handleException(OAuth2Exception e) throws Exception {
        if (logger.isWarnEnabled()) {
            logger.warn(HANDLING_ERROR + e.getClass().getSimpleName() + ", " + e.getMessage());
        }
        return getExceptionTranslator().translate(e);
    }

    private ResponseEntity<OAuth2AccessToken> getResponse(OAuth2AccessToken accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Cache-Control", "no-store");
        headers.set("Pragma", "no-cache");
        headers.set("Content-Type", "application/json");
        return new ResponseEntity<>(accessToken, headers, HttpStatus.OK);
    }

    private boolean isRefreshTokenRequest(Map<String, String> parameters) {
        return "refresh_token".equals(parameters.get("grant_type"));
    }

    private boolean isAuthCodeRequest(Map<String, String> parameters) {
        return "authorization_code".equals(parameters.get(OAuth2Utils.GRANT_TYPE)) && parameters.get("code") != null;
    }

    public void setOAuth2RequestValidator(OAuth2RequestValidator oAuth2RequestValidator) {
        this.oAuth2RequestValidator = oAuth2RequestValidator;
    }

    public void setAllowedRequestMethods(Set<HttpMethod> allowedRequestMethods) {
        this.allowedRequestMethods = allowedRequestMethods;
    }
}
