package org.cloudfoundry.identity.uaa.provider.oauth;

import com.github.benmanes.caffeine.cache.Ticker;
import org.cloudfoundry.identity.uaa.cache.StaleUrlCache;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.RawExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager.AuthenticationData;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.time.Duration;
import java.util.Map;

import static com.google.common.collect.Lists.newArrayList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
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

class ExternalOAuthAuthenticationManagerGithubTest {

    private static final String AUTH_URL = "https://github.example.com/login/oauth/authorize";
    private static final String TOKEN_URL = "https://github.example.com/login/oauth/access_token";
    private static final String USER_INFO_URL = "https://api.github.example.com/user";

    private MockRestServiceServer mockGithubServer;

    private ExternalOAuthAuthenticationManager authManager;
    private String origin;

    @BeforeEach
    void beforeEach() throws Exception {
        origin = "github";
        String zoneId = "zoneId";
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(zoneId);
        IdentityZoneHolder.set(identityZone);

        IdentityProviderProvisioning identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        IdentityProvider<RawExternalOAuthIdentityProviderDefinition> provider = new IdentityProvider<>();
        RawExternalOAuthIdentityProviderDefinition providerConfig = new RawExternalOAuthIdentityProviderDefinition();
        providerConfig.setResponseType("code");
        providerConfig.setAuthUrl(URI.create(AUTH_URL).toURL());
        providerConfig.setTokenUrl(URI.create(TOKEN_URL).toURL());
        providerConfig.setUserInfoUrl(URI.create(USER_INFO_URL).toURL());
        providerConfig.setScopes(newArrayList(new String[]{"openid", "email"}));
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
        String uaaIssuerBaseUrl = "http://uaa.example.com";
        TokenEndpointBuilder tokenEndpointBuilder = new TokenEndpointBuilder(uaaIssuerBaseUrl);

        RestTemplate trustingRestTemplate = null;
        RestTemplate nonTrustingRestTemplate = new RestTemplate();
        mockGithubServer = MockRestServiceServer.createServer(nonTrustingRestTemplate);

        OidcMetadataFetcher oidcMetadataFetcher = new OidcMetadataFetcher(
                new StaleUrlCache(Duration.ofMinutes(2), new TimeServiceImpl(), 10, Ticker.disabledTicker()),
                trustingRestTemplate,
                nonTrustingRestTemplate
        );
        authManager = new ExternalOAuthAuthenticationManager(identityProviderProvisioning, new IdentityZoneManagerImpl(), trustingRestTemplate,
                nonTrustingRestTemplate, tokenEndpointBuilder, new KeyInfoService(uaaIssuerBaseUrl), oidcMetadataFetcher);
    }

    @AfterEach
    void afterEach() {
        IdentityZoneHolder.clear();
    }

    @Test
    void getExternalAuthenticationDetails_doesNotThrowWhenIdTokenIsValid() {
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

        String userInfoResponse = """
                {
                  "login": "octocat",
                  "id": 1,
                  "type": "User",
                  "site_admin": false,
                  "name": "monalisa octocat",
                  "company": "GitHub",
                  "email": "octocat@github.example.com"
                }""";
        mockGithubServer.expect(method(GET))
                .andExpect(requestTo(USER_INFO_URL))
                .andExpect(header(ACCEPT, APPLICATION_JSON_VALUE))
                .andExpect(header(AUTHORIZATION, "Bearer " + accessToken))
                .andRespond(withSuccess(userInfoResponse, APPLICATION_JSON));

        ExternalOAuthCodeToken oauth2Authentication = new ExternalOAuthCodeToken(null, origin, "http://uaa.example.com/login/callback/github", idToken, "accesstoken", "signedrequest");

        // When
        AuthenticationData authenticationData = authManager.getExternalAuthenticationDetails(oauth2Authentication);

        // Then
        mockGithubServer.verify();
        assertThat(authenticationData.getUsername()).isEqualTo("octocat@github.example.com");

        Map<String, Object> claims = authenticationData.getClaims();
        assertThat(claims)
                .containsEntry("login", "octocat")
                .containsEntry("name", "monalisa octocat")
                .containsEntry("email", "octocat@github.example.com");
    }
}
