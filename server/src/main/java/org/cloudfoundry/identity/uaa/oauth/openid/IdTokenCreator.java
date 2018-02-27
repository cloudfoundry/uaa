package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.joda.time.DateTime;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.MultiValueMap;

import java.util.Date;
import java.util.Set;

public class IdTokenCreator {
    private String issuerUrl;
    private TokenValidityResolver tokenValidityResolver;
    private UaaUserDatabase uaaUserDatabase;

    public IdTokenCreator(String issuerUrl,
                          TokenValidityResolver tokenValidityResolver,
                          UaaUserDatabase uaaUserDatabase) {
        this.issuerUrl = issuerUrl;
        this.tokenValidityResolver = tokenValidityResolver;
        this.uaaUserDatabase = uaaUserDatabase;
    }

    public IdToken create(String clientId,
                          String userId,
                          Date authTime,
                          Set<String> amr,
                          Set<String> acr,
                          OAuth2Authentication uaaAuthentication) throws Exception {

        Date expiryDate = tokenValidityResolver.resolveAccessTokenValidity(clientId);
        String issuer = UaaTokenUtils.constructTokenEndpointUrl(issuerUrl);
        Date issuedAt = DateTime.now().toDate();

        UaaUser uaaUser = uaaUserDatabase.retrieveUserById(userId);
        Set<String> scopes = ((UaaAuthentication) uaaAuthentication.getUserAuthentication()).getExternalGroups();

        if (!uaaAuthentication.getOAuth2Request().getScope().contains("roles")
            || ((UaaAuthentication) uaaAuthentication.getUserAuthentication()).getExternalGroups() == null
            || ((UaaAuthentication) uaaAuthentication.getUserAuthentication()).getExternalGroups().isEmpty()) {
            scopes = null;
        }

        MultiValueMap<String, String> userAttributes =
            ((UaaAuthentication) uaaAuthentication.getUserAuthentication()).getUserAttributes();

        if (!uaaAuthentication.getOAuth2Request().getScope().contains("user_attributes")) {
            userAttributes = null;
        }

        return new IdToken(
            userId,
            clientId,
            issuer,
            expiryDate,
            issuedAt,
            authTime,
            amr,
            acr,
            clientId,
            uaaUser.getGivenName(),
            uaaUser.getFamilyName(),
            uaaUser.getPreviousLogonTime(),
            uaaUser.getPhoneNumber(),
            scopes,
            userAttributes);
    }
}
