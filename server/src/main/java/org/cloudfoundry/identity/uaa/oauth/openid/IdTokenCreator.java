package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.oauth.TokenActor;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ACR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ACT;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AMR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUD;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUTH_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AZP;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL_VERIFIED;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXPIRY_IN_SECONDS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.FAMILY_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GIVEN_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.IAT;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.NONCE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ORIGIN;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PHONE_NUMBER;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PREVIOUS_LOGON_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.REVOCATION_SIGNATURE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ZONE_ID;
import static org.cloudfoundry.identity.uaa.util.UaaTokenUtils.getRevocableTokenSignature;

public class IdTokenCreator {
    private static final String ROLES_SCOPE = "roles";
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final TokenEndpointBuilder tokenEndpointBuilder;
    private final IdentityZoneManager identityZoneManager;
    private TimeService timeService;
    private final TokenValidityResolver tokenValidityResolver;
    private final UaaUserDatabase uaaUserDatabase;
    private final MultitenantClientServices multitenantClientServices;
    private final Set<String> excludedClaims;

    public IdTokenCreator(final TokenEndpointBuilder tokenEndpointBuilder,
            final TimeService timeService,
            final TokenValidityResolver tokenValidityResolver,
            final UaaUserDatabase uaaUserDatabase,
            final MultitenantClientServices multitenantClientServices,
            final Set<String> excludedClaims,
            final IdentityZoneManager identityZoneManager) {
        this.timeService = timeService;
        this.tokenValidityResolver = tokenValidityResolver;
        this.uaaUserDatabase = uaaUserDatabase;
        this.multitenantClientServices = multitenantClientServices;
        this.excludedClaims = excludedClaims;
        this.tokenEndpointBuilder = tokenEndpointBuilder;
        this.identityZoneManager = identityZoneManager;
    }

    public IdToken create(
            ClientDetails clientDetails,
            UaaUser uaaUser,
            UserAuthenticationData userAuthenticationData,
            TokenActor tokenActor
    ) throws IdTokenCreationException {
        Date expiryDate = tokenValidityResolver.resolve(clientDetails.getClientId());
        Date issuedAt = timeService.getCurrentDate();

        String givenName = getIfScopeContainsProfile(uaaUser.getGivenName(), userAuthenticationData.scopes);
        String familyName = getIfScopeContainsProfile(uaaUser.getFamilyName(), userAuthenticationData.scopes);
        String phoneNumber = getIfScopeContainsProfile(uaaUser.getPhoneNumber(), userAuthenticationData.scopes);

        String issuerUrl = tokenEndpointBuilder.getTokenEndpoint(identityZoneManager.getCurrentIdentityZone());
        String identityZoneId = identityZoneManager.getCurrentIdentityZoneId();
        Map<String, List<String>> userAttributes = buildUserAttributes(userAuthenticationData, uaaUser);
        Set<String> roles = buildRoles(userAuthenticationData, uaaUser);

        String clientTokenSalt = (String) clientDetails.getAdditionalInformation().get(ClientConstants.TOKEN_SALT);
        String revSig = getRevocableTokenSignature(uaaUser, clientTokenSalt, clientDetails.getClientId(), clientDetails.getClientSecret());

        IdToken idToken = new IdToken(
                getIfNotExcluded(uaaUser.getId(), USER_ID),
                getIfNotExcluded(newArrayList(clientDetails.getClientId()), AUD),
                getIfNotExcluded(issuerUrl, ISS),
                getIfNotExcluded(expiryDate, EXPIRY_IN_SECONDS),
                getIfNotExcluded(issuedAt, IAT),
                getIfNotExcluded(userAuthenticationData.authTime, AUTH_TIME),
                getIfNotExcluded(userAuthenticationData.authenticationMethods, AMR),
                getIfNotExcluded(userAuthenticationData.contextClassRef, ACR),
                getIfNotExcluded(clientDetails.getClientId(), AZP),
                getIfNotExcluded(givenName, GIVEN_NAME),
                getIfNotExcluded(familyName, FAMILY_NAME),
                getIfNotExcluded(uaaUser.getPreviousLogonTime(), PREVIOUS_LOGON_TIME),
                getIfNotExcluded(phoneNumber, PHONE_NUMBER),
                getIfNotExcluded(roles, ROLES),
                getIfNotExcluded(userAttributes, USER_ATTRIBUTES),
                getIfNotExcluded(uaaUser.isVerified(), EMAIL_VERIFIED),
                getIfNotExcluded(userAuthenticationData.nonce, NONCE),
                getIfNotExcluded(uaaUser.getEmail(), EMAIL),
                getIfNotExcluded(clientDetails.getClientId(), CID),
                getIfNotExcluded(userAuthenticationData.grantType, GRANT_TYPE),
                getIfNotExcluded(uaaUser.getUsername(), USER_NAME),
                getIfNotExcluded(identityZoneId, ZONE_ID),
                getIfNotExcluded(uaaUser.getOrigin(), ORIGIN),
                getIfNotExcluded(userAuthenticationData.jti, JTI),
                getIfNotExcluded(revSig, REVOCATION_SIGNATURE)
        );
        idToken.setTokenActor(getIfNotExcluded(tokenActor, ACT));
        return idToken;
    }

    private String getIfScopeContainsProfile(String value, Set<String> scopes) {
        return scopes.contains("profile") ? value : null;
    }

    private <T> T getIfNotExcluded(T value, String excludedKey) {
        return this.excludedClaims.contains(excludedKey) ? null : value;
    }

    private Map<String, List<String>> buildUserAttributes(UserAuthenticationData userAuthenticationData, UaaUser user) {
        Map<String, List<String>> attributes = null;
        boolean requestedAttributes = userAuthenticationData.scopes.contains("user_attributes");
        if (requestedAttributes) {
            attributes = userAuthenticationData.userAttributes;
        }

        if (requestedAttributes && attributes == null) {
            logger.debug("Requested id_token containing {}, but no saved attributes available for user with id:{}. Ensure storeCustomAttributes is enabled for origin:{} in zone:{}.", ClaimConstants.USER_ATTRIBUTES, user.getId(), user.getOrigin(), identityZoneManager.getCurrentIdentityZoneId());
        }

        return attributes;
    }

    private Set<String> buildRoles(UserAuthenticationData userAuthenticationData, UaaUser user) {
        boolean requestedRoles = userAuthenticationData.scopes.contains(ROLES_SCOPE);
        Set<String> roles = null;
        if (requestedRoles
                && userAuthenticationData.roles != null
                && !userAuthenticationData.roles.isEmpty()) {
            roles = userAuthenticationData.roles;
        }

        if (requestedRoles && roles == null) {
            logger.debug("Requested id_token containing user roles, but no saved roles available for user with id:{}. Ensure storeCustomAttributes is enabled for origin:{} in zone:{}.", user.getId(), user.getOrigin(), identityZoneManager.getCurrentIdentityZoneId());
        }

        return roles;
    }

    public void setTimeService(TimeService timeService) {
        this.timeService = timeService;
    }
}
