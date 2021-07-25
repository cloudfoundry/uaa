package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.TokenValidation;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.oauth2.provider.ClientDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.cloudfoundry.identity.uaa.util.TokenValidation.buildAccessTokenValidator;
import static org.cloudfoundry.identity.uaa.util.TokenValidation.buildRefreshTokenValidator;

public class TokenValidationService {
    private RevocableTokenProvisioning revocableTokenProvisioning;
    private TokenEndpointBuilder tokenEndpointBuilder;
    private UaaUserDatabase userDatabase;
    private MultitenantClientServices multitenantClientServices;
    private KeyInfoService keyInfoService;

    public TokenValidationService(RevocableTokenProvisioning revocableTokenProvisioning,
                                  TokenEndpointBuilder tokenEndpointBuilder,
                                  UaaUserDatabase userDatabase,
                                  MultitenantClientServices multitenantClientServices,
                                  KeyInfoService keyInfoService) {
        this.revocableTokenProvisioning = revocableTokenProvisioning;
        this.tokenEndpointBuilder = tokenEndpointBuilder;
        this.userDatabase = userDatabase;
        this.multitenantClientServices = multitenantClientServices;
        this.keyInfoService = keyInfoService;
    }

    public TokenValidation validateToken(String token, boolean isAccessToken) {
        if (!UaaTokenUtils.isJwtToken(token)) {
            RevocableToken revocableToken;
            try {
                revocableToken = revocableTokenProvisioning.retrieve(token, IdentityZoneHolder.get().getId());
            } catch (EmptyResultDataAccessException ex) {
                throw new TokenRevokedException("The token expired, was revoked, or the token ID is incorrect.");
            }
            token = revocableToken.getValue();
        }

        TokenValidation tokenValidation = isAccessToken ?
                buildAccessTokenValidator(token, keyInfoService) : buildRefreshTokenValidator(token, keyInfoService);
        tokenValidation
                .checkRevocableTokenStore(revocableTokenProvisioning)
                .checkIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));

        ClientDetails client = tokenValidation.getClientDetails(multitenantClientServices);
        UaaUser user = tokenValidation.getUserDetails(userDatabase);
        tokenValidation
                .checkClientAndUser(client, user);

        List<String> clientSecrets = new ArrayList<>();
        List<String> revocationSignatureList = new ArrayList<>();
        if (client.getClientSecret() != null) {
            clientSecrets.addAll(Arrays.asList(client.getClientSecret().split(" ")));
        } else {
            revocationSignatureList.add(UaaTokenUtils.getRevocableTokenSignature(client, null, user));
        }

        for (String clientSecret : clientSecrets) {
            revocationSignatureList.add(UaaTokenUtils.getRevocableTokenSignature(client, clientSecret, user));
        }

        tokenValidation = tokenValidation.checkRevocationSignature(revocationSignatureList);

        return tokenValidation;
    }

    public void setUserDatabase(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }
}
