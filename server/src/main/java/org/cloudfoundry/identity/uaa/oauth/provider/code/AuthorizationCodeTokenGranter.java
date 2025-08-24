package org.cloudfoundry.identity.uaa.oauth.provider.code;

import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationException;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AbstractTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.UaaSecurityContextUtils;
import org.springframework.security.core.Authentication;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.RedirectMismatchException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Moved class AuthorizationCodeTokenGranter implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class AuthorizationCodeTokenGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "authorization_code";

    private final AuthorizationCodeServices authorizationCodeServices;

    public AuthorizationCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
            AuthorizationCodeServices authorizationCodeServices, ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
        this(tokenServices, authorizationCodeServices, clientDetailsService, requestFactory, GRANT_TYPE);
    }

    protected AuthorizationCodeTokenGranter(AuthorizationServerTokenServices tokenServices, AuthorizationCodeServices authorizationCodeServices,
            ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, String grantType) {
        super(tokenServices, clientDetailsService, requestFactory, grantType);
        this.authorizationCodeServices = authorizationCodeServices;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        return getOAuth2Authentication(client, tokenRequest, authorizationCodeServices, null);
    }

    protected static OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest,
            AuthorizationCodeServices authorizationCodeServices, PkceValidationService pkceService) {

        Map<String, String> parameters = tokenRequest.getRequestParameters();
        String authorizationCode = parameters.get("code");
        String redirectUri = parameters.get(OAuth2Utils.REDIRECT_URI);

        if (authorizationCode == null) {
            throw new InvalidRequestException("An authorization code must be supplied.");
        }

        OAuth2Authentication storedAuth;

        if (pkceService != null) {
            /*
             * PKCE code verifier parameter length and charset validation
             */
            String codeVerifier = parameters.get(PkceValidationService.CODE_VERIFIER);
            if (codeVerifier != null && !PkceValidationService.isCodeVerifierParameterValid(codeVerifier)) {
                throw new InvalidRequestException("Code verifier length must between 43 and 128 and use only [A-Z],[a-z],[0-9],_,.,-,~ characters.");
            }
            storedAuth = getStoredCodeAuthentication(authorizationCodeServices, authorizationCode);
            /*
             * PKCE code verifier parameter verification
             */
            try {
                if (!pkceService.checkAndValidate(storedAuth.getOAuth2Request().getRequestParameters(), codeVerifier, client)) {
                    // has PkceValidation service and validation failed
                    throw new InvalidGrantException("Invalid code verifier: " + codeVerifier);
                }
            } catch (PkceValidationException exception) {
                // during the validation one of the PKCE parameters missing
                throw new InvalidGrantException("PKCE error: " + exception.getMessage());
            }
            // No pkceService defined or Pkce validation successfully passed
        } else {
            storedAuth = getStoredCodeAuthentication(authorizationCodeServices, authorizationCode);
        }

        OAuth2Request pendingOAuth2Request = storedAuth.getOAuth2Request();
        // https://jira.springsource.org/browse/SECOAUTH-333
        // This might be null, if the authorization was done without the redirect_uri
        // parameter
        String redirectUriApprovalParameter = pendingOAuth2Request.getRequestParameters().get(OAuth2Utils.REDIRECT_URI);

        if ((redirectUri != null || redirectUriApprovalParameter != null)
                && !pendingOAuth2Request.getRedirectUri().equals(redirectUri)) {
            throw new RedirectMismatchException("Redirect URI mismatch.");
        }

        String pendingClientId = pendingOAuth2Request.getClientId();
        String clientId = tokenRequest.getClientId();
        if (clientId != null && !clientId.equals(pendingClientId)) {
            // just a sanity check.
            throw new InvalidClientException("Client ID mismatch");
        }
        // Secret is not required in the authorization request, so it won't be available
        // in the pendingAuthorizationRequest. We do want to check that a secret is
        // provided
        // in the token request, but that happens elsewhere.

        Map<String, String> combinedParameters = new HashMap<>(
                pendingOAuth2Request.getRequestParameters());
        // Combine the parameters adding the new ones last so they override if there are
        // any clashes
        combinedParameters.putAll(parameters);

        // Make a new stored request with the combined parameters
        OAuth2Request finalStoredOAuth2Request = pendingOAuth2Request.createOAuth2Request(combinedParameters);

        Authentication userAuth = storedAuth.getUserAuthentication();

        String clientAuthentication = UaaSecurityContextUtils.getClientAuthenticationMethod();
        if (clientAuthentication != null) {
            finalStoredOAuth2Request.getExtensions().put(ClaimConstants.CLIENT_AUTH_METHOD, clientAuthentication);
        }

        return new OAuth2Authentication(finalStoredOAuth2Request, userAuth);
    }

    private static OAuth2Authentication getStoredCodeAuthentication(AuthorizationCodeServices authorizationCodeServices, String authorizationCode) {
        return Optional.ofNullable(authorizationCodeServices.consumeAuthorizationCode(authorizationCode)).orElseThrow(
                () -> new InvalidGrantException("Invalid authorization code: " + authorizationCode));
    }
}
