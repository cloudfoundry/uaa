package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.joda.time.DateTimeUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.TOKEN_SALT;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class IdTokenCreatorTest {
    private String issuerUrl;
    private String uaaUrl;
    private String clientId;
    private String userId;
    private IdTokenCreator tokenCreator;
    private Date expDate;
    private Date iatDate;
    private Date authTime;
    private Set<String> amr;
    private Set<String> acr;

    private UaaUserDatabase mockUaaUserDatabase;
    private String givenName;
    private String familyName;
    private String email;
    private UaaUser user;
    private BaseClientDetails clientDetails;
    private long previousLogonTime;
    private String phoneNumber;
    private Set<String> roles;
    private Set<String> scopes;
    private MultiValueMap<String, String> userAttributes;
    private String nonce;
    private UserAuthenticationData userAuthenticationData;
    private Set<String> excludedClaims;
    private String grantType;
    private String userName;
    private String zoneId;
    private String origin;
    private String jti;
    private String clientsecret;
    private String tokensalt;
    private IdentityZoneManager mockIdentityZoneManager;

    @BeforeEach
    void setup() throws Exception {
        issuerUrl = "http://localhost:8080/uaa/oauth/token";
        uaaUrl = "http://localhost:8080/uaa";
        clientId = "clientId";
        clientsecret = "clientsecret";
        tokensalt = "tokensalt";
        userId = "userId";
        zoneId = "zoneId";
        jti = "accessTokenId";

        expDate = new Date(100_000);
        authTime = new Date(500);
        amr = new HashSet<String>() {{
            add("mfa");
            add("ext");
        }};
        acr = new HashSet<String>() {{
            add("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
        }};
        givenName = "bruce";
        familyName = "denis";
        email = "u@p.i";
        previousLogonTime = 12345;
        phoneNumber = "(123) 456-7890";
        roles = new HashSet<>();
        roles.add("cook");
        roles.add("plumber");

        userAttributes = new LinkedMultiValueMap<>();
        userAttributes.add("k1", "v11");
        userAttributes.add("k1", "v12");
        userAttributes.add("k2", "v21");

        nonce = "becreative";
        grantType = "password";

        scopes = new HashSet<String>() {{
            add("openid");
            add("roles");
            add("profile");
            add("user_attributes");
        }};
        origin = "user-origin";
        userName = "username";

        user = new UaaUser(new UaaUserPrototype()
                .withEmail(email)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withPhoneNumber(phoneNumber)
                .withId("id1234")
                .withEmail("spongebob@krustykrab.com")
                .withUsername(userName)
                .withPreviousLogonSuccess(previousLogonTime)
                .withVerified(true)
                .withOrigin(origin)
        );

        iatDate = new Date(1L);

        TokenValidityResolver mockTokenValidityResolver = mock(TokenValidityResolver.class);
        when(mockTokenValidityResolver.resolve(clientId)).thenReturn(expDate);

        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(IdentityZone.getUaa());
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId);

        mockUaaUserDatabase = mock(UaaUserDatabase.class);
        when(mockUaaUserDatabase.retrieveUserById(userId)).thenReturn(user);

        userAuthenticationData = new UserAuthenticationData(
                authTime,
                amr,
                acr,
                scopes,
                roles,
                userAttributes,
                nonce,
                grantType,
                jti);
        excludedClaims = new HashSet<>();

        MultitenantClientServices mockMultitenantClientServices = mock(MultitenantClientServices.class);
        clientDetails = new BaseClientDetails();
        clientDetails.setClientId(clientId);
        clientDetails.setClientSecret(clientsecret);

        HashMap<String, String> additionalInfo = new HashMap<String, String>() {{
            put(TOKEN_SALT, tokensalt);
        }};
        clientDetails.setAdditionalInformation(additionalInfo);
        when(mockMultitenantClientServices.loadClientByClientId(clientId, zoneId)).thenReturn(clientDetails);

        TimeService mockTimeService = mock(TimeService.class);
        when(mockTimeService.getCurrentDate()).thenCallRealMethod();
        when(mockTimeService.getCurrentTimeMillis()).thenReturn(1L);
        tokenCreator = new IdTokenCreator(
                new TokenEndpointBuilder(uaaUrl),
                mockTimeService,
                mockTokenValidityResolver,
                mockUaaUserDatabase,
                mockMultitenantClientServices,
                excludedClaims,
                mockIdentityZoneManager);
    }

    @AfterEach
    void teardown() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @Test
    void create_includesStandardClaims() throws IdTokenCreationException {
        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData);

        assertThat(idToken, is(notNullValue()));
        assertThat(idToken.sub, is("id1234"));
        assertThat(idToken.aud, hasItem(clientId));
        assertThat(idToken.iss, is(issuerUrl));
        assertThat(idToken.exp, is(expDate));
        assertThat(idToken.iat, is(iatDate));
        assertThat(idToken.authTime, is(authTime));
        assertThat(idToken.amr, hasItems(is("mfa"), is("ext")));
        assertThat(idToken.acr, hasItems(is("urn:oasis:names:tc:SAML:2.0:ac:classes:Password")));
        assertThat(idToken.azp, is(clientId));
    }

    @Test
    void create_includesAdditionalClaims() throws IdTokenCreationException {
        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData);

        assertThat(idToken, is(notNullValue()));
        assertThat(idToken.givenName, is(givenName));
        assertThat(idToken.familyName, is(familyName));
        assertThat(idToken.previousLogonTime, is(previousLogonTime));
        assertThat(idToken.phoneNumber, is(phoneNumber));
        assertThat(idToken.roles, is(roles));
        assertThat(idToken.userAttributes, is(userAttributes));
        assertThat(idToken.scope, hasItem("openid"));
        assertThat(idToken.emailVerified, is(true));
        assertThat(idToken.nonce, is(nonce));
        assertThat(idToken.email, is("spongebob@krustykrab.com"));
        assertThat(idToken.clientId, is(clientId));
        assertThat(idToken.grantType, is(grantType));
        assertThat(idToken.userName, is(userName));
        assertThat(idToken.zid, is(zoneId));
        assertThat(idToken.origin, is(origin));
        assertThat(idToken.jti, is("accessTokenId"));
        assertThat(idToken.revSig, is("a039bd5"));
    }

    @Test
    void create_includesEmailVerified() throws IdTokenCreationException {
        user.setVerified(false);
        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData);
        assertThat(idToken.emailVerified, is(false));
    }

    @Test
    void create_doesntPopulateRolesWhenScopeDoesntContainRoles() throws IdTokenCreationException {
        scopes.clear();
        scopes.add("openid");

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData);

        assertThat(idToken.roles, nullValue());
    }

    @Test
    void create_setsRolesToNullIfThereAreNoRoles() throws IdTokenCreationException {
        roles.clear();

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData);

        assertThat(idToken.roles, nullValue());
    }

    @Test
    void create_setsRolesToNullIfRolesAreNull() throws IdTokenCreationException {
        userAuthenticationData = new UserAuthenticationData(
                authTime,
                amr,
                acr,
                scopes,
                null,
                userAttributes,
                nonce,
                grantType,
                jti);

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData);

        assertThat(idToken.roles, nullValue());
    }

    @Test
    void create_doesntPopulateUserAttributesWhenScopeDoesntContainUserAttributes() throws IdTokenCreationException {
        scopes.clear();
        scopes.add("openid");

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData);

        assertThat(idToken.userAttributes, nullValue());
    }

    @Test
    void create_doesntSetUserAttributesIfTheyAreNull() throws IdTokenCreationException {
        userAuthenticationData = new UserAuthenticationData(
                authTime,
                amr,
                acr,
                scopes,
                roles,
                null,
                nonce,
                grantType,
                jti);

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData);

        assertThat(idToken.userAttributes, nullValue());
    }

    @Test
    void create_doesntPopulateNamesAndPhone_whenNoProfileScopeGiven() throws IdTokenCreationException {
        scopes.remove("profile");

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData);

        assertThat(idToken.givenName, is(nullValue()));
        assertThat(idToken.familyName, is(nullValue()));
        assertThat(idToken.phoneNumber, is(nullValue()));
    }

    @Test
    void create_doesntIncludesExcludedClaims() throws IdTokenCreationException {
        excludedClaims.add(ClaimConstants.USER_ID);
        excludedClaims.add(ClaimConstants.AUD);
        excludedClaims.add(ClaimConstants.ISS);
        excludedClaims.add(ClaimConstants.EXPIRY_IN_SECONDS);
        excludedClaims.add(ClaimConstants.IAT);
        excludedClaims.add(ClaimConstants.AUTH_TIME);
        excludedClaims.add(ClaimConstants.AMR);
        excludedClaims.add(ClaimConstants.ACR);
        excludedClaims.add(ClaimConstants.AZP);
        excludedClaims.add(ClaimConstants.GIVEN_NAME);
        excludedClaims.add(ClaimConstants.FAMILY_NAME);
        excludedClaims.add(ClaimConstants.PREVIOUS_LOGON_TIME);
        excludedClaims.add(ClaimConstants.PHONE_NUMBER);
        excludedClaims.add(ClaimConstants.ROLES);
        excludedClaims.add(ClaimConstants.USER_ATTRIBUTES);
        excludedClaims.add(ClaimConstants.EMAIL_VERIFIED);
        excludedClaims.add(ClaimConstants.NONCE);
        excludedClaims.add(ClaimConstants.EMAIL);
        excludedClaims.add(ClaimConstants.CID);
        excludedClaims.add(ClaimConstants.GRANT_TYPE);
        excludedClaims.add(ClaimConstants.USER_NAME);
        excludedClaims.add(ClaimConstants.ZONE_ID);
        excludedClaims.add(ClaimConstants.ORIGIN);
        excludedClaims.add(ClaimConstants.JTI);
        excludedClaims.add(ClaimConstants.REVOCATION_SIGNATURE);

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData);

        assertThat(idToken.sub, is(nullValue()));
        assertThat(idToken.aud, is(nullValue()));
        assertThat(idToken.iss, is(nullValue()));
        assertThat(idToken.exp, is(nullValue()));
        assertThat(idToken.iat, is(nullValue()));
        assertThat(idToken.authTime, is(nullValue()));
        assertThat(idToken.amr, is(nullValue()));
        assertThat(idToken.acr, is(nullValue()));
        assertThat(idToken.azp, is(nullValue()));
        assertThat(idToken.givenName, is(nullValue()));
        assertThat(idToken.familyName, is(nullValue()));
        assertThat(idToken.previousLogonTime, is(nullValue()));
        assertThat(idToken.phoneNumber, is(nullValue()));
        assertThat(idToken.roles, is(nullValue()));
        assertThat(idToken.userAttributes, is(nullValue()));
        assertThat(idToken.emailVerified, is(nullValue()));
        assertThat(idToken.nonce, is(nullValue()));
        assertThat(idToken.email, is(nullValue()));
        assertThat(idToken.clientId, is(nullValue()));
        assertThat(idToken.grantType, is(nullValue()));
        assertThat(idToken.userName, is(nullValue()));
        assertThat(idToken.zid, is(nullValue()));
        assertThat(idToken.origin, is(nullValue()));
        assertThat(idToken.jti, is(nullValue()));
        assertThat(idToken.revSig, is(nullValue()));
    }

    @Test
    void idToken_containsZonifiedIssuerUrl() throws Exception {
        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        when(mockIdentityZone.isUaa()).thenReturn(false);
        when(mockIdentityZone.getSubdomain()).thenReturn("myzone");
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData);

        assertThat(idToken.iss, is("http://myzone.localhost:8080/uaa/oauth/token"));
    }
}