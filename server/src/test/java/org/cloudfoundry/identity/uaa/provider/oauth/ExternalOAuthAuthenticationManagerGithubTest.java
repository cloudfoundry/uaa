package org.cloudfoundry.identity.uaa.provider.oauth;

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.net.URL;
import java.time.Duration;
import java.util.Map;

import org.cloudfoundry.identity.uaa.cache.ExpiringUrlCache;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.RawExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager.AuthenticationData;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

public class ExternalOAuthAuthenticationManagerGithubTest {
    
    private static final String AUTH_URL = "https://github.example.com/login/oauth/authorize";
    private static final String TOKEN_URL = "https://github.example.com/login/oauth/access_token";
    private static final String USER_INFO_URL = "https://api.github.example.com/user";

    private MockRestServiceServer mockGithubServer;

    private ExternalOAuthAuthenticationManager authManager;
    private String origin;
    private String zoneId;

    private RawExternalOAuthIdentityProviderDefinition providerConfig;
    private String uaaIssuerBaseUrl;
    private TokenEndpointBuilder tokenEndpointBuilder;

    @Before
    public void setup() throws Exception {
        origin = "github";
        zoneId = "zoneId";
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(zoneId);
        IdentityZoneHolder.set(identityZone);

        IdentityProviderProvisioning identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        IdentityProvider<RawExternalOAuthIdentityProviderDefinition> provider = new IdentityProvider<>();
        providerConfig = new RawExternalOAuthIdentityProviderDefinition();
        providerConfig.setResponseType("code");
        providerConfig.setAuthUrl(new URL(AUTH_URL));
        providerConfig.setTokenUrl(new URL(TOKEN_URL));
        providerConfig.setUserInfoUrl(new URL(USER_INFO_URL));
        providerConfig.setScopes(newArrayList(new String[] { "openid", "email" }));
        providerConfig.setAddShadowUserOnLogin(true); // the default anyway
        providerConfig.setRelyingPartyId("github_app_client_id");
        providerConfig.setRelyingPartySecret("github_app_client_secret");
        providerConfig.setSkipSslValidation(false); // the default
        providerConfig.setClientAuthInBody(true);
        Map<String, Object> attributeMappings = map(
                entry("given_name", "login"),
                entry("family_name", "name"),
                entry("user_name", "email")
        );
        providerConfig.setAttributeMappings(attributeMappings);
        provider.setConfig(providerConfig);
        when(identityProviderProvisioning.retrieveByOrigin(origin, zoneId)).thenReturn(provider);
        uaaIssuerBaseUrl = "http://uaa.example.com";
        tokenEndpointBuilder = new TokenEndpointBuilder(uaaIssuerBaseUrl);

        RestTemplate trustingRestTemplate = null;
        RestTemplate nonTrustingRestTemplate = new RestTemplate();
        mockGithubServer = MockRestServiceServer.createServer(nonTrustingRestTemplate);

        OidcMetadataFetcher oidcMetadataFetcher = new OidcMetadataFetcher(
            new ExpiringUrlCache(Duration.ofMinutes(2), new TimeServiceImpl(), 10),
            trustingRestTemplate,
            nonTrustingRestTemplate
        );
        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, trustingRestTemplate,
                nonTrustingRestTemplate, tokenEndpointBuilder, new KeyInfoService(uaaIssuerBaseUrl), oidcMetadataFetcher);
    }

    @After
    public void cleanup() {
        IdentityZoneHolder.clear();
    }


    @Test
    public void getExternalAuthenticationDetails_doesNotThrowWhenIdTokenIsValid() {
        // Given
        String idToken = "xyz";
        String accessToken = "e72e16c7e42f292c6912e7710c838347ae178b4a";
        String tokenResponse = "{\"access_token\":\"" + accessToken + "\", \"scope\":\"repo,gist\", \"token_type\":\"bearer\"}";
        mockGithubServer.expect(method(POST))
            .andExpect(requestTo(TOKEN_URL))
            .andExpect(header(ACCEPT, APPLICATION_JSON_VALUE))
//            .andExpect(content().json("{\n"
//                    + "\"client_id\": \"github_app_client_id\",\n"
//                    + "\"client_secret\": \"github_app_client_secret\",\n"
//                    + "\"code\": \"" + idToken + "\"\n"
//                    + "}"))
            .andRespond(withSuccess(tokenResponse, APPLICATION_JSON));

        String userInfoResponse = "{\n"
                + "  \"login\": \"octocat\",\n"
                + "  \"id\": 1,\n"
                + "  \"type\": \"User\",\n"
                + "  \"site_admin\": false,\n"
                + "  \"name\": \"monalisa octocat\",\n"
                + "  \"company\": \"GitHub\",\n"
                + "  \"email\": \"octocat@github.example.com\"\n"
                + "}";
        mockGithubServer.expect(method(GET))
            .andExpect(requestTo(USER_INFO_URL))
            .andExpect(header(ACCEPT, APPLICATION_JSON_VALUE))
            .andExpect(header(AUTHORIZATION, "token " + accessToken))
            .andRespond(withSuccess(userInfoResponse, APPLICATION_JSON));
        
        ExternalOAuthCodeToken oauth2Authentication = new ExternalOAuthCodeToken(null, origin, "http://uaa.example.com/login/callback/github", idToken, "accesstoken", "signedrequest");

        // When
        AuthenticationData authenticationData = authManager.getExternalAuthenticationDetails(oauth2Authentication);

        // Then
        mockGithubServer.verify();
        assertThat(authenticationData.getUsername(), is(equalTo("octocat@github.example.com")));

        Map<String, Object> claims = authenticationData.getClaims();
        assertThat(claims.get("login"), is(equalTo("octocat")));
        assertThat(claims.get("name"), is(equalTo("monalisa octocat")));
        assertThat(claims.get("email"), is(equalTo("octocat@github.example.com")));
        
    }
    
}
