package org.cloudfoundry.identity.uaa.oauth.openid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.joda.time.DateTime;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.net.URISyntaxException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ACR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AMR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUD;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUTH_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AZP;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL_VERIFIED;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXP;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.FAMILY_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GIVEN_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.IAT;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.NONCE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PHONE_NUMBER;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PREVIOUS_LOGON_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ZONE_ID;

public class IdTokenCreator {
    private final Log logger = LogFactory.getLog(getClass());
    private String issuerUrlBase;
    private TokenValidityResolver tokenValidityResolver;
    private UaaUserDatabase uaaUserDatabase;
    private Set<String> excludedClaims;

    public IdTokenCreator(String issuerUrlBase,
                          TokenValidityResolver tokenValidityResolver,
                          UaaUserDatabase uaaUserDatabase,
                          Set<String> excludedClaims) {
        this.tokenValidityResolver = tokenValidityResolver;
        this.uaaUserDatabase = uaaUserDatabase;
        this.excludedClaims = excludedClaims;
        this.issuerUrlBase = issuerUrlBase;
    }

    public IdToken create(String clientId,
                          String userId,
                          UserAuthenticationData userAuthenticationData) throws IdTokenCreationException {
        Date expiryDate = tokenValidityResolver.resolve(clientId);
        Date issuedAt = DateTime.now().toDate();

        UaaUser uaaUser;
        try {
            uaaUser = uaaUserDatabase.retrieveUserById(userId);
        } catch (UsernameNotFoundException e) {
            logger.error("Could not create ID token for unknown user " + userId, e);
            throw new IdTokenCreationException();
        }

        Set<String> roles = buildRoles(userAuthenticationData);
        Map<String, List<String>> userAttributes = buildUserAttributes(userAuthenticationData);

        String givenName = getIfScopeContainsProfile(uaaUser.getGivenName(), userAuthenticationData.scopes);
        String familyName = getIfScopeContainsProfile(uaaUser.getFamilyName(), userAuthenticationData.scopes);
        String phoneNumber = getIfScopeContainsProfile(uaaUser.getPhoneNumber(), userAuthenticationData.scopes);

        String issuerUrl;
        try {
            issuerUrl = UaaTokenUtils.constructTokenEndpointUrl(this.issuerUrlBase);
        } catch (URISyntaxException e) {
            logger.error("Could not construct the issuer url", e);
            throw new IdTokenCreationException();
        }

        return new IdToken(
            getIfNotExcluded(userId, USER_ID),
            getIfNotExcluded(newArrayList(clientId), AUD),
            getIfNotExcluded(issuerUrl, ISS),
            getIfNotExcluded(expiryDate, EXP),
            getIfNotExcluded(issuedAt, IAT),
            getIfNotExcluded(userAuthenticationData.time, AUTH_TIME),
            getIfNotExcluded(userAuthenticationData.methods, AMR),
            getIfNotExcluded(userAuthenticationData.contextClassRef, ACR),
            getIfNotExcluded(clientId, AZP),
            getIfNotExcluded(givenName, GIVEN_NAME),
            getIfNotExcluded(familyName, FAMILY_NAME),
            getIfNotExcluded(uaaUser.getPreviousLogonTime(), PREVIOUS_LOGON_TIME),
            getIfNotExcluded(phoneNumber, PHONE_NUMBER),
            getIfNotExcluded(roles, ROLES),
            getIfNotExcluded(userAttributes, USER_ATTRIBUTES),
            getIfNotExcluded(uaaUser.isVerified(), EMAIL_VERIFIED),
            getIfNotExcluded(userAuthenticationData.nonce, NONCE),
            getIfNotExcluded(uaaUser.getEmail(), EMAIL),
            getIfNotExcluded(clientId, CID),
            getIfNotExcluded(userAuthenticationData.grantType, GRANT_TYPE),
            getIfNotExcluded(uaaUser.getUsername(), USER_NAME),
            getIfNotExcluded(IdentityZoneHolder.get().getId(), ZONE_ID));
    }

    private String getIfScopeContainsProfile(String value, Set<String> scopes) {
        return scopes.contains("profile") ? value : null;
    }

    private <T> T getIfNotExcluded(T value, String excludedKey) {
        return this.excludedClaims.contains(excludedKey) ? null : value;
    }

    private Map<String, List<String>> buildUserAttributes(UserAuthenticationData userAuthenticationData) {
        if (!userAuthenticationData.scopes.contains("user_attributes")) {
            return null;
        }
        return userAuthenticationData.userAttributes;
    }

    private Set<String> buildRoles(UserAuthenticationData userAuthenticationData) {
        if (!userAuthenticationData.scopes.contains("roles")
            || userAuthenticationData.roles == null
            || userAuthenticationData.roles.isEmpty()) {
            return null;
        }
        return userAuthenticationData.roles;
    }
}
