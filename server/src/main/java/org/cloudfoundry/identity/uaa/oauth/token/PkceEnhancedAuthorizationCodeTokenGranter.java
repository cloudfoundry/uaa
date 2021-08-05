package org.cloudfoundry.identity.uaa.oauth.token;

import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationException;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

public class PkceEnhancedAuthorizationCodeTokenGranter extends AuthorizationCodeTokenGranter {
    
    private final AuthorizationCodeServices authorizationCodeServices;
    
    private PkceValidationService pkceValidationService;

    public PkceEnhancedAuthorizationCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
            AuthorizationCodeServices authorizationCodeServices, ClientDetailsService clientDetailsService,
            OAuth2RequestFactory requestFactory) {
        super(tokenServices, authorizationCodeServices, clientDetailsService, requestFactory);
        this.authorizationCodeServices = authorizationCodeServices;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {

        Map<String, String> parameters = tokenRequest.getRequestParameters();
        String authorizationCode = parameters.get("code");
        String redirectUri = parameters.get(OAuth2Utils.REDIRECT_URI);

        if (authorizationCode == null) {
            throw new InvalidRequestException("An authorization code must be supplied.");
        }
        
        /*
         * PKCE code verifier parameter length and charset validation
         */
        String codeVerifier = parameters.get(PkceValidationService.CODE_VERIFIER);
        if (codeVerifier != null && !PkceValidationService.isCodeVerifierParameterValid(codeVerifier)) {
            throw new InvalidRequestException("Code verifier length must between 43 and 128 and use only [A-Z],[a-z],[0-9],_,.,-,~ characters.");
        }

        OAuth2Authentication storedAuth = authorizationCodeServices.consumeAuthorizationCode(authorizationCode);
        if (storedAuth == null) {
            throw new InvalidGrantException("Invalid authorization code: " + authorizationCode);
        }
        
        /*
         * PKCE code verifier parameter verification
         */
        try {
            if (pkceValidationService != null && !pkceValidationService.checkAndValidate(storedAuth.getOAuth2Request().getRequestParameters(), codeVerifier)) {
                // has PkceValidation service and validation failed
                throw new InvalidGrantException("Invalid code verifier: " + codeVerifier);
            }
        } catch (PkceValidationException exception) {
            // during the validation one of the PKCE parameters missing
            throw new InvalidGrantException("PKCE error: "+ exception.getMessage());
        }
        // No pkceValidationService defined or Pkce validation successfully passed
        
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

        Map<String, String> combinedParameters = new HashMap<String, String>(
                pendingOAuth2Request.getRequestParameters());
        // Combine the parameters adding the new ones last so they override if there are
        // any clashes
        combinedParameters.putAll(parameters);

        // Make a new stored request with the combined parameters
        OAuth2Request finalStoredOAuth2Request = pendingOAuth2Request.createOAuth2Request(combinedParameters);

        Authentication userAuth = storedAuth.getUserAuthentication();

        return new OAuth2Authentication(finalStoredOAuth2Request, userAuth);

    }

	public PkceValidationService getPkceValidationService() {
		return pkceValidationService;
	}

	public void setPkceValidationService(PkceValidationService pkceValidationService) {
		this.pkceValidationService = pkceValidationService;
	}

}
