package org.cloudfoundry.identity.uaa.oauth;

import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.dao.EmptyResultDataAccessException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA.buildAccessTokenValidator;
import static org.cloudfoundry.identity.uaa.util.JwtTokenSignedByThisUAA.buildRefreshTokenValidator;

public class TokenValidationService {
    private final RevocableTokenProvisioning revocableTokenProvisioning;
    private final TokenEndpointBuilder tokenEndpointBuilder;
    private final UaaUserDatabase userDatabase;
    private final MultitenantClientServices multitenantClientServices;
    private final KeyInfoService keyInfoService;

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

    public JwtTokenSignedByThisUAA validateToken(String token, boolean isAccessToken) {
        if (!UaaTokenUtils.isJwtToken(token)) {
            RevocableToken revocableToken;
            try {
                revocableToken = revocableTokenProvisioning.retrieve(token, IdentityZoneHolder.get().getId());
            } catch (EmptyResultDataAccessException ex) {
                throw new TokenRevokedException("The token expired, was revoked, or the token ID is incorrect.");
            }
            token = revocableToken.getValue();
        }

        JwtTokenSignedByThisUAA jwtToken = isAccessToken ?
                buildAccessTokenValidator(token, keyInfoService) : buildRefreshTokenValidator(token, keyInfoService);
        jwtToken
                .checkRevocableTokenStore(revocableTokenProvisioning)
                .checkIssuer(tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));

        ClientDetails client = jwtToken.getClientDetails(multitenantClientServices);
        UaaUser user = jwtToken.getUserDetails(userDatabase);
        jwtToken
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

        jwtToken = jwtToken.checkRevocationSignature(revocationSignatureList);

        return jwtToken;
    }
}
