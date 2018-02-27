package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URISyntaxException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest({UaaTokenUtils.class, IdentityZoneHolder.class})
public class IdTokenCreatorTest {
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

    private UaaUserDatabase uaaUserDatabase;
    private String givenName;
    private String familyName;
    private String email;
    private UaaUser user;
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

    @Before
    public void setup() throws Exception {
        issuerUrl = "http://localhost:8080/uaa/oauth/token";
        uaaUrl = "http://localhost:8080/uaa";
        clientId = "clientId";
        userId = "userId";
        zoneId = "zoneId";
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
            //add(UaaTokenServices.OPEN_ID);
            add("openid");
            add("roles");
            add("profile");
            add("user_attributes");
        }};

        userName = "username";
        user = new UaaUser(new UaaUserPrototype()
            .withEmail(email)
            .withGivenName(givenName)
            .withFamilyName(familyName)
            .withPhoneNumber(phoneNumber)
            .withId("id")
            .withEmail("spongebob@krustykrab.com")
            .withUsername(userName)
            .withPreviousLogonSuccess(previousLogonTime)
            .withVerified(true)
        );

        DateTimeUtils.setCurrentMillisFixed(1l);
        iatDate = DateTime.now().toDate();

        TokenValidityResolver tokenValidityResolver = mock(TokenValidityResolver.class);
        when(tokenValidityResolver.resolve(clientId)).thenReturn(expDate);

        PowerMockito.mockStatic(UaaTokenUtils.class);
        when(UaaTokenUtils.constructTokenEndpointUrl(uaaUrl)).thenReturn(issuerUrl);
        PowerMockito.mockStatic(IdentityZoneHolder.class);
        when(IdentityZoneHolder.get()).thenReturn(new IdentityZone() {{ setId(zoneId); }});

        uaaUserDatabase = mock(UaaUserDatabase.class);
        when(uaaUserDatabase.retrieveUserById(userId)).thenReturn(user);

        userAuthenticationData = new UserAuthenticationData(
            authTime,
            amr,
            acr,
            scopes,
            roles,
            userAttributes,
            nonce,
            grantType);
        excludedClaims = new HashSet<>();

        tokenCreator = new IdTokenCreator(uaaUrl, tokenValidityResolver, uaaUserDatabase, excludedClaims);
    }

    @After
    public void teardown() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @Test
    public void create_includesStandardClaims() throws IdTokenCreationException {
        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken, is(notNullValue()));
        assertThat(idToken.sub, is(userId));
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
    public void create_includesAdditionalClaims() throws IdTokenCreationException {
        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

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
    }

    @Test
    public void create_includesEmailVerified() throws IdTokenCreationException {
        user.setVerified(false);
        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);
        assertThat(idToken.emailVerified, is(false));
    }

    @Test
    public void create_doesntPopulateRolesWhenScopeDoesntContainRoles() throws IdTokenCreationException {
        scopes.clear();
        scopes.add("openid");

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.roles, nullValue());
    }

    @Test
    public void create_setsRolesToNullIfThereAreNoRoles() throws IdTokenCreationException {
        roles.clear();

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.roles, nullValue());
    }

    @Test
    public void create_setsRolesToNullIfRolesAreNull() throws IdTokenCreationException {
        userAuthenticationData = new UserAuthenticationData(
            authTime,
            amr,
            acr,
            scopes,
            null,
            userAttributes,
            nonce,
            grantType);

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.roles, nullValue());
    }

    @Test
    public void create_doesntPopulateUserAttributesWhenScopeDoesntContainUserAttributes() throws IdTokenCreationException {
        scopes.clear();
        scopes.add("openid");

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.userAttributes, nullValue());
    }

    @Test
    public void create_doesntSetUserAttributesIfTheyAreNull() throws IdTokenCreationException {
        userAuthenticationData = new UserAuthenticationData(
            authTime,
            amr,
            acr,
            scopes,
            roles,
            null, nonce, grantType);

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.userAttributes, nullValue());
    }

    @Test
    public void create_doesntPopulateNamesAndPhone_whenNoProfileScopeGiven() throws IdTokenCreationException {
        scopes.remove("profile");

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.givenName, is(nullValue()));
        assertThat(idToken.familyName, is(nullValue()));
        assertThat(idToken.phoneNumber, is(nullValue()));
    }

    @Test
    public void create_doesntIncludesExcludedClaims() throws IdTokenCreationException {
        excludedClaims.add(ClaimConstants.USER_ID);
        excludedClaims.add(ClaimConstants.AUD);
        excludedClaims.add(ClaimConstants.ISS);
        excludedClaims.add(ClaimConstants.EXP);
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

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

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
    }

    @Test(expected = IdTokenCreationException.class)
    public void whenUserIdNotFound_throwsException() throws Exception {
        when(uaaUserDatabase.retrieveUserById("missing-user")).thenThrow(UsernameNotFoundException.class);

        tokenCreator.create(clientId, "missing-user", userAuthenticationData);
    }

    @Test
    public void idToken_containsZonifiedIssuerUrl() throws Exception {
        when(UaaTokenUtils.constructTokenEndpointUrl(uaaUrl)).thenReturn("http://myzone.localhost:8080/uaa/oauth/token");

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.iss, is("http://myzone.localhost:8080/uaa/oauth/token"));
    }

    @Test(expected = IdTokenCreationException.class)
    public void whenIssuerUrlIsInvalid_throwsRuntimeException() throws Exception {
        when(UaaTokenUtils.constructTokenEndpointUrl(uaaUrl)).thenThrow(URISyntaxException.class);

        tokenCreator.create(clientId, userId, userAuthenticationData);
    }
}