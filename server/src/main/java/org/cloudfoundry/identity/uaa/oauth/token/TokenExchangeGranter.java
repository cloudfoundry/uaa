package org.cloudfoundry.identity.uaa.oauth.token;

import com.nimbusds.jwt.JWTClaimsSet;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AbstractTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.provider.oauth.TokenActor;
import org.cloudfoundry.identity.uaa.security.beans.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.text.ParseException;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_EXCHANGE_IMPERSONATE_CLIENT_PERMISSION;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ACCESS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ID;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.hasText;

public class TokenExchangeGranter extends AbstractTokenGranter {

    final DefaultSecurityContextAccessor defaultSecurityContextAccessor;

    private final MultitenantClientServices clientDetailsService;

    public TokenExchangeGranter(AuthorizationServerTokenServices tokenServices,
                                MultitenantClientServices clientDetailsService,
                                OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE_TOKEN_EXCHANGE);
        defaultSecurityContextAccessor = new DefaultSecurityContextAccessor();
        this.clientDetailsService = clientDetailsService;
    }

    protected Authentication validateRequest(TokenRequest request) {
        if (defaultSecurityContextAccessor.isUser()) {
            if (request == null ||
                    request.getRequestParameters() == null ||
                    request.getRequestParameters().isEmpty()) {
                throw new InvalidGrantException("Missing subject token request object");
            }
            if (request.getRequestParameters().get("grant_type") == null) {
                throw new InvalidGrantException("Missing grant type");
            }
            if (!GRANT_TYPE_TOKEN_EXCHANGE.equals(request.getRequestParameters().get("grant_type"))) {
                throw new InvalidGrantException("Invalid grant type");
            }
            String subjectToken = request.getRequestParameters().get("subject_token");
            if (subjectToken == null || !hasText(subjectToken)) {
                throw new InvalidGrantException("Missing subject token");
            }
            String subjectTokenType = request.getRequestParameters().get("subject_token_type");
            if (subjectTokenType == null) {
                throw new InvalidGrantException("Missing subject token type");
            }
            if (! (TOKEN_TYPE_ID.equals(subjectTokenType) || TOKEN_TYPE_ACCESS.equals(subjectTokenType)) ) {
                throw new InvalidGrantException("Invalid subject token type, only " + TOKEN_TYPE_ID +
                        " and " + TOKEN_TYPE_ACCESS + " are supported");
            }
            String requestedTokenType = request.getRequestParameters().get("requested_token_type");
            if (hasText(requestedTokenType) && !TOKEN_TYPE_ACCESS.equals(requestedTokenType)) {
                throw new InvalidGrantException("Invalid requested token type, only " + TOKEN_TYPE_ACCESS + " is supported");
            }

            ClientDetails client;
            try {
                client = clientDetailsService.loadClientByClientId(request.getClientId());
                if (!client.getAuthorizedGrantTypes().contains(GRANT_TYPE_TOKEN_EXCHANGE)) {
                    throw new InvalidGrantException("Unsupported grant type");
                }
            } catch (ClientRegistrationException e) {
                throw new InvalidGrantException("Invalid client_id");
            }
            String audience = request.getRequestParameters().get("audience");
            if (hasText(audience)) {
                try {
                    clientDetailsService.loadClientByClientId(audience);
                } catch (ClientRegistrationException e) {
                    throw new InvalidGrantException("Invalid audience");
                }
                String requiredImpersonationAuthority =
                        String.format(TOKEN_EXCHANGE_IMPERSONATE_CLIENT_PERMISSION, audience);
                long count = client.getAuthorities()==null ? 0l : client
                        .getAuthorities()
                        .stream()
                        .filter(ga -> requiredImpersonationAuthority.equals(ga.getAuthority()))
                        .count();
                if (count == 0) {
                    throw new InvalidGrantException(
                            "Insufficient permissions, " + requiredImpersonationAuthority +
                                    " is missing."
                    );

                }
            }
        } else {
            throw new InvalidGrantException("User authentication not found");
        }
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @Override
    public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
        if (!GRANT_TYPE_TOKEN_EXCHANGE.equals(grantType)) {
            return null;
        }
        validateRequest(tokenRequest);
        TokenActor tokenActor = getTokenActor(tokenRequest);
        String clientId = tokenRequest.getRequestParameters().get("audience");
        if (hasText(clientId)) {
            tokenRequest = new TokenRequest(
                    tokenRequest.getRequestParameters(),
                    clientId,
                    tokenRequest.getScope(),
                    tokenRequest.getGrantType()
            );
        }
        tokenRequest.setTokenActor(tokenActor);
        return super.grant(grantType, tokenRequest);
    }

    protected TokenActor getTokenActor(TokenRequest tokenRequest) {
        String subjectToken = tokenRequest.getRequestParameters().get("subject_token");
        JWTClaimsSet claims = JwtHelper.decode(subjectToken).getClaimSet();
        String clientId = tokenRequest.getClientId();
        try {
            return new TokenActor(
                    claims.getSubject(),
                    claims.getIssuer(),
                    clientId,
                    claims.getClaimAsString(ClaimConstants.USER_NAME),
                    claims.getClaimAsString(ClaimConstants.USER_ID),
                    claims.getClaimAsString(ClaimConstants.ORIGIN)
            );
        } catch (ParseException p) {
            logger.debug("Unable to parse subject_token claims", p);
            throw new InvalidGrantException("Unable to parse subject_token claims");
        }
    }

    @Override
    protected void validateGrantType(String grantType, ClientDetails clientDetails) {

    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        Authentication userAuth = SecurityContextHolder.getContext().getAuthentication();
        OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, userAuth);
    }
}
