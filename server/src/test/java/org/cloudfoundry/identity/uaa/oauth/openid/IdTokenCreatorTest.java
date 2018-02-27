package org.cloudfoundry.identity.uaa.oauth.openid;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
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
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
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

    private UaaAuthentication uaaAuthentication;
    private OAuth2Authentication oAuth2Authentication;
    private Set<String> scopes;
    private OAuth2Request oAuthRequest;
    private MultiValueMap<String, String> userAttributes;

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

        scopes = new HashSet<String>() {{
            //add(UaaTokenServices.OPEN_ID);
            add("openid");
            add("roles");
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
        );

        DateTimeUtils.setCurrentMillisFixed(1l);
        iatDate = DateTime.now().toDate();

        TokenValidityResolver tokenValidityResolver = mock(TokenValidityResolver.class);
        when(tokenValidityResolver.resolveAccessTokenValidity(clientId)).thenReturn(expDate);

        PowerMockito.mockStatic(UaaTokenUtils.class);
        when(UaaTokenUtils.constructTokenEndpointUrl(uaaUrl)).thenReturn(issuerUrl);

        uaaUserDatabase = mock(UaaUserDatabase.class);
        when(uaaUserDatabase.retrieveUserById(userId)).thenReturn(user);

        uaaAuthentication = mock(UaaAuthentication.class);
        when(uaaAuthentication.getExternalGroups()).thenReturn(roles);
        when(uaaAuthentication.getUserAttributes()).thenReturn(userAttributes);

        oAuth2Authentication = mock(OAuth2Authentication.class);
        when(oAuth2Authentication.getUserAuthentication()).thenReturn(uaaAuthentication);

        oAuthRequest = spy(OAuth2Request.class);
        oAuthRequest = oAuthRequest.narrowScope(scopes);

        when(oAuth2Authentication.getOAuth2Request()).thenReturn(oAuthRequest);

        tokenCreator = new IdTokenCreator(uaaUrl, tokenValidityResolver, uaaUserDatabase);
    }

    @After
    public void teardown() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @Test
    public void create_includesStandardClaims() throws Exception {
        IdToken idToken = tokenCreator.create(clientId, userId, authTime, amr, acr, oAuth2Authentication);

        assertThat(idToken, is(notNullValue()));
        assertThat(idToken.sub, is(userId));
        assertThat(idToken.aud, is(clientId));
        assertThat(idToken.iss, is(issuerUrl));
        assertThat(idToken.exp, is(expDate));
        assertThat(idToken.iat, is(iatDate));
        assertThat(idToken.authTime, is(authTime));
        assertThat(idToken.amr, hasItems(is("mfa"), is("ext")));
        assertThat(idToken.acr, hasItems(is("urn:oasis:names:tc:SAML:2.0:ac:classes:Password")));
        assertThat(idToken.azp, is(clientId));
    }

    @Test
    public void create_includesAdditionalClaims() throws Exception {
        IdToken idToken = tokenCreator.create(clientId, userId, authTime, amr, acr, oAuth2Authentication);

        assertThat(idToken, is(notNullValue()));
        assertThat(idToken.givenName, is(givenName));
        assertThat(idToken.familyName, is(familyName));
        assertThat(idToken.previousLogonTime, is(previousLogonTime));
        assertThat(idToken.phoneNumber, is(phoneNumber));
        assertThat(idToken.roles, is(roles));
        assertThat(idToken.userAttributes, is(userAttributes));
        assertThat(idToken.scope, is("openid"));

        // TODO EMAIL_VERIFIED <----- this story
    }

    @Test
    public void create_doesntPopulateRolesWhenScopeDoesntContainRoles() throws Exception {
        scopes.clear();
        scopes.add("openid");
        oAuthRequest = oAuthRequest.narrowScope(scopes);
        when(oAuth2Authentication.getOAuth2Request()).thenReturn(oAuthRequest);

        IdToken idToken = tokenCreator.create(clientId, userId, authTime, amr, acr, oAuth2Authentication);

        assertThat(idToken.roles, nullValue());
    }

    @Test
    public void create_setsRolesToNullIfThereAreNoRoles() throws Exception {
        roles.clear();

        IdToken idToken = tokenCreator.create(clientId, userId, authTime, amr, acr, oAuth2Authentication);

        assertThat(idToken.roles, nullValue());
    }

    @Test
    public void create_setsRolesToNullIfRolesAreNull() throws Exception {
        when(uaaAuthentication.getExternalGroups()).thenReturn(null);

        IdToken idToken = tokenCreator.create(clientId, userId, authTime, amr, acr, oAuth2Authentication);

        assertThat(idToken.roles, nullValue());
    }

    @Test
    public void create_doesntPopulateUserAttributesWhenScopeDoesntContainUserAttributes() throws Exception {
        scopes.clear();
        scopes.add("openid");
        oAuthRequest = oAuthRequest.narrowScope(scopes);
        when(oAuth2Authentication.getOAuth2Request()).thenReturn(oAuthRequest);

        IdToken idToken = tokenCreator.create(clientId, userId, authTime, amr, acr, oAuth2Authentication);

        assertThat(idToken.userAttributes, nullValue());
    }

    @Test
    public void create_doesntSetUserAttributesIfTheyAreNull() throws Exception {
        when(uaaAuthentication.getUserAttributes()).thenReturn(null);

        IdToken idToken = tokenCreator.create(clientId, userId, authTime, amr, acr, oAuth2Authentication);

        assertThat(idToken.userAttributes, nullValue());
    }
}
