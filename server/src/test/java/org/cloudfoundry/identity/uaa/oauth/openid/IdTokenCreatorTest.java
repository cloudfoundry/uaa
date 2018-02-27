package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
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

    @Before
    public void setup() throws Exception {
        issuerUrl = "http://localhost:8080/uaa/oauth/token";
        uaaUrl = "http://localhost:8080/uaa";
        clientId = "clientId";
        userId = "userId";
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

        scopes = new HashSet<String>() {{
            //add(UaaTokenServices.OPEN_ID);
            add("openid");
            add("roles");
            add("profile");
            add("user_attributes");
        }};

        user = new UaaUser(new UaaUserPrototype()
            .withEmail(email)
            .withGivenName(givenName)
            .withFamilyName(familyName)
            .withPhoneNumber(phoneNumber)
            .withId("id")
            .withUsername("username")
            .withPreviousLogonSuccess(previousLogonTime)
            .withVerified(true)
        );

        DateTimeUtils.setCurrentMillisFixed(1l);
        iatDate = DateTime.now().toDate();

        TokenValidityResolver tokenValidityResolver = mock(TokenValidityResolver.class);
        when(tokenValidityResolver.resolveAccessTokenValidity(clientId)).thenReturn(expDate);

        PowerMockito.mockStatic(UaaTokenUtils.class);
        when(UaaTokenUtils.constructTokenEndpointUrl(uaaUrl)).thenReturn(issuerUrl);

        uaaUserDatabase = mock(UaaUserDatabase.class);
        when(uaaUserDatabase.retrieveUserById(userId)).thenReturn(user);

        userAuthenticationData = new UserAuthenticationData(
            authTime,
            amr,
            acr,
            scopes,
            roles,
            userAttributes,
            nonce);
        excludedClaims = new HashSet<>();

        tokenCreator = new IdTokenCreator(uaaUrl, tokenValidityResolver, uaaUserDatabase, excludedClaims);
    }

    @After
    public void teardown() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @Test(expected = RuntimeException.class)
    public void shouldNotAllowCreatingATokenCreatorIfIssuerUrlIsNotValid() throws URISyntaxException {
        when(UaaTokenUtils.constructTokenEndpointUrl(uaaUrl)).thenThrow(URISyntaxException.class);
        new IdTokenCreator(uaaUrl, null, uaaUserDatabase, excludedClaims);
    }

    @Test
    public void create_includesStandardClaims() {
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
    public void create_includesAdditionalClaims() {
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
    }

    @Test
    public void create_includesEmailVerified() {
        user.setVerified(false);
        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);
        assertThat(idToken.emailVerified, is(false));
    }

    @Test
    public void create_doesntPopulateRolesWhenScopeDoesntContainRoles() {
        scopes.clear();
        scopes.add("openid");

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.roles, nullValue());
    }

    @Test
    public void create_setsRolesToNullIfThereAreNoRoles() {
        roles.clear();

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.roles, nullValue());
    }

    @Test
    public void create_setsRolesToNullIfRolesAreNull() {
        userAuthenticationData = new UserAuthenticationData(
            authTime,
            amr,
            acr,
            scopes,
            null,
            userAttributes, nonce);

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.roles, nullValue());
    }

    @Test
    public void create_doesntPopulateUserAttributesWhenScopeDoesntContainUserAttributes() {
        scopes.clear();
        scopes.add("openid");

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.userAttributes, nullValue());
    }

    @Test
    public void create_doesntSetUserAttributesIfTheyAreNull() {
        userAuthenticationData = new UserAuthenticationData(
            authTime,
            amr,
            acr,
            scopes,
            roles,
            null, nonce);

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.userAttributes, nullValue());
    }

    @Test
    public void create_doesntPopulateNamesAndPhone_whenNoProfileScopeGiven() {
        scopes.remove("profile");

        IdToken idToken = tokenCreator.create(clientId, userId, userAuthenticationData);

        assertThat(idToken.givenName, is(nullValue()));
        assertThat(idToken.familyName, is(nullValue()));
        assertThat(idToken.phoneNumber, is(nullValue()));
    }

    @Test
    public void create_doesntIncludesExcludedClaims() {
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
    }
}