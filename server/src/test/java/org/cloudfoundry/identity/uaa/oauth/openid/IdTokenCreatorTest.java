package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.oauth.TokenActor;
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
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientConstants.TOKEN_SALT;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class IdTokenCreatorTest {
    private String issuerUrl;
    private String clientId;
    private IdTokenCreator tokenCreator;
    private Date expDate;
    private Date iatDate;
    private Date authTime;
    private Set<String> amr;
    private Set<String> acr;

    private String givenName;
    private String familyName;
    private UaaUser user;
    private UaaClientDetails clientDetails;
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
    private IdentityZoneManager mockIdentityZoneManager;

    private TokenActor tokenActor = new TokenActor(
            "actorSubject",
            "actorIssuer",
            "actorClientId",
            "actorUsername",
            "actorUserId",
            "actorOrigin"
    );

    @BeforeEach
    void setup() throws Exception {
        issuerUrl = "http://localhost:8080/uaa/oauth/token";
        String uaaUrl = "http://localhost:8080/uaa";
        clientId = "clientId";
        String clientsecret = "clientsecret";
        String tokensalt = "tokensalt";
        String userId = "userId";
        zoneId = "zoneId";
        jti = "accessTokenId";

        expDate = new Date(100_000);
        authTime = new Date(500);
        amr = new HashSet<>() {
            {
                add("mfa");
                add("ext");
            }
        };
        acr = new HashSet<>() {
            {
                add("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
            }
        };
        givenName = "bruce";
        familyName = "denis";
        String email = "u@p.i";
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

        scopes = new HashSet<>() {
            {
                add("openid");
                add("roles");
                add("profile");
                add("user_attributes");
            }
        };
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

        UaaUserDatabase mockUaaUserDatabase = mock(UaaUserDatabase.class);
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
                null,
                jti);
        excludedClaims = new HashSet<>();

        MultitenantClientServices mockMultitenantClientServices = mock(MultitenantClientServices.class);
        clientDetails = new UaaClientDetails();
        clientDetails.setClientId(clientId);
        clientDetails.setClientSecret(clientsecret);

        HashMap<String, String> additionalInfo = new HashMap<>();
        additionalInfo.put(TOKEN_SALT, tokensalt);
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
        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData, tokenActor);

        assertThat(idToken).isNotNull();
        assertThat(idToken.sub).isEqualTo("id1234");
        assertThat(idToken.aud).contains(clientId);
        assertThat(idToken.iss).isEqualTo(issuerUrl);
        assertThat(idToken.exp).isEqualTo(expDate);
        assertThat(idToken.iat).isEqualTo(iatDate);
        assertThat(idToken.authTime).isEqualTo(authTime);
        assertThat(idToken.amr).contains("mfa", "ext");
        assertThat(idToken.acr).contains("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
        assertThat(idToken.azp).isEqualTo(clientId);
    }

    @Test
    void create_includesAdditionalClaims() throws IdTokenCreationException {
        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData, tokenActor);

        assertThat(idToken).isNotNull();
        assertThat(idToken.givenName).isEqualTo(givenName);
        assertThat(idToken.familyName).isEqualTo(familyName);
        assertThat(idToken.previousLogonTime).isEqualTo(previousLogonTime);
        assertThat(idToken.phoneNumber).isEqualTo(phoneNumber);
        assertThat(idToken.roles).isEqualTo(roles);
        assertThat(idToken.userAttributes).isEqualTo(userAttributes);
        assertThat(idToken.scope).contains("openid");
        assertThat(idToken.emailVerified).isTrue();
        assertThat(idToken.nonce).isEqualTo(nonce);
        assertThat(idToken.email).isEqualTo("spongebob@krustykrab.com");
        assertThat(idToken.clientId).isEqualTo(clientId);
        assertThat(idToken.grantType).isEqualTo(grantType);
        assertThat(idToken.userName).isEqualTo(userName);
        assertThat(idToken.zid).isEqualTo(zoneId);
        assertThat(idToken.origin).isEqualTo(origin);
        assertThat(idToken.jti).isEqualTo("accessTokenId");
        assertThat(idToken.revSig).isEqualTo("a039bd5");
        assertThat(idToken.getTokenActor().get(ClaimConstants.ISS)).isEqualTo(tokenActor.getIssuer());
    }

    @Test
    void create_includesEmailVerified() throws IdTokenCreationException {
        user.setVerified(false);
        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData, tokenActor);
        assertThat(idToken.emailVerified).isFalse();
    }

    @Test
    void create_doesntPopulateRolesWhenScopeDoesntContainRoles() throws IdTokenCreationException {
        scopes.clear();
        scopes.add("openid");

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData, tokenActor);

        assertThat(idToken.roles).isNull();
    }

    @Test
    void create_setsRolesToNullIfThereAreNoRoles() throws IdTokenCreationException {
        roles.clear();

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData, tokenActor);

        assertThat(idToken.roles).isNull();
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
                null,
                jti);

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData, tokenActor);

        assertThat(idToken.roles).isNull();
    }

    @Test
    void create_doesntPopulateUserAttributesWhenScopeDoesntContainUserAttributes() throws IdTokenCreationException {
        scopes.clear();
        scopes.add("openid");

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData, tokenActor);

        assertThat(idToken.userAttributes).isNull();
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
                null,
                jti);

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData, tokenActor);

        assertThat(idToken.userAttributes).isNull();
    }

    @Test
    void create_doesntPopulateNamesAndPhone_whenNoProfileScopeGiven() throws IdTokenCreationException {
        scopes.remove("profile");

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData, tokenActor);

        assertThat(idToken.givenName).isNull();
        assertThat(idToken.familyName).isNull();
        assertThat(idToken.phoneNumber).isNull();
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
        excludedClaims.add(ClaimConstants.ACT);

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData, tokenActor);

        assertThat(idToken.sub).isNull();
        assertThat(idToken.aud).isNull();
        assertThat(idToken.iss).isNull();
        assertThat(idToken.exp).isNull();
        assertThat(idToken.iat).isNull();
        assertThat(idToken.authTime).isNull();
        assertThat(idToken.amr).isNull();
        assertThat(idToken.acr).isNull();
        assertThat(idToken.azp).isNull();
        assertThat(idToken.givenName).isNull();
        assertThat(idToken.familyName).isNull();
        assertThat(idToken.previousLogonTime).isNull();
        assertThat(idToken.phoneNumber).isNull();
        assertThat(idToken.roles).isNull();
        assertThat(idToken.userAttributes).isNull();
        assertThat(idToken.emailVerified).isNull();
        assertThat(idToken.nonce).isNull();
        assertThat(idToken.email).isNull();
        assertThat(idToken.clientId).isNull();
        assertThat(idToken.grantType).isNull();
        assertThat(idToken.userName).isNull();
        assertThat(idToken.zid).isNull();
        assertThat(idToken.origin).isNull();
        assertThat(idToken.jti).isNull();
        assertThat(idToken.revSig).isNull();
        assertThat(idToken.getTokenActor()).isNull();
    }

    @Test
    void idToken_containsZonifiedIssuerUrl() throws Exception {
        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        when(mockIdentityZone.isUaa()).thenReturn(false);
        when(mockIdentityZone.getSubdomain()).thenReturn("myzone");
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);

        IdToken idToken = tokenCreator.create(clientDetails, user, userAuthenticationData, tokenActor);

        assertThat(idToken.iss).isEqualTo("http://myzone.localhost:8080/uaa/oauth/token");
    }
}