package org.cloudfoundry.identity.uaa.mock.token;

import org.apache.commons.codec.binary.Base64;
import org.assertj.core.api.Assertions;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtClientAuthentication;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.net.URI;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.jwk.RsaJsonWebKeyTestUtils.SAMPLE_RSA_PRIVATE_KEY;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

public class TokenExchangeMockMvcBase extends AbstractTokenMockMvcTests {
    enum ClientAuthType {
        BASIC, FORM, CLIENT_ASSERTION
    }

    public record AuthorizationServer(
            String identifier,
            MockMvcUtils.IdentityZoneCreationResult zone,
            IdentityProvider<OIDCIdentityProviderDefinition> identityProvider,
            ClientDetails client,
            ScimUser user
    ) {
        @Override
        public String identifier() {
            return identifier;
        }

        @Override
        public MockMvcUtils.IdentityZoneCreationResult zone() {
            return zone;
        }

        @Override
        public IdentityProvider<OIDCIdentityProviderDefinition> identityProvider() {
            return identityProvider;
        }

        @Override
        public ClientDetails client() {
            return client;
        }

        @Override
        public ScimUser user() {
            return user;
        }
    }

    public record ThreeWayUAASetup(
            AuthorizationServer thirdPartyIdp,
            Map<String, Object> thirdPartyTokens,
            AuthorizationServer controlServer,
            Map<String, Object> controlServerTokens,
            AuthorizationServer workerServer
    ) {
        @Override
        public AuthorizationServer thirdPartyIdp() {
            return thirdPartyIdp;
        }

        @Override
        public Map<String, Object> thirdPartyTokens() {
            return thirdPartyTokens;
        }

        @Override
        public AuthorizationServer controlServer() {
            return controlServer;
        }

        @Override
        public Map<String, Object> controlServerTokens() {
            return controlServerTokens;
        }

        @Override
        public AuthorizationServer workerServer() {
            return workerServer;
        }

        public Jwt getTokenClaims(String token, String tokenKey, String serverKey) {
            assertThat(token)
                    .withFailMessage(String.format("Server: %s does not have a token under key: %s", serverKey, tokenKey))
                    .isNotNull()
                    .isNotEmpty();

            try {
                return JwtHelper.decode(token);
            } catch (RuntimeException e) {
                Assertions.fail(
                        String.format("Unable to decode token: %s for server: %s and key: %s", token, serverKey, tokenKey)
                );
            }
            return null;
        }
    }

    ThreeWayUAASetup getThreeWayUaaSetUp() throws Exception {
        //simulate an outside IDP
        AuthorizationServer thirdParty = getAuthorizationServer(
                "3rd",
                provider -> null,
                (client) -> {
                    client.setScope(List.of("openid"));
                    client.setAuthorizedGrantTypes(List.of("password", "refresh_token"));
                    return client;
                },
                user -> user
        );

        //create control UAA - the one to rule them all
        AuthorizationServer controlServer = getAuthorizationServer(
                "ctl",
                (provider) -> {
                    provider.getConfig().setLinkText("OIDC Provider: " + thirdParty.zone.getIdentityZone().getSubdomain());
                    provider.getConfig().setTokenKey(getTokenVerificationKey(thirdParty.zone.getIdentityZone()));
                    provider.getConfig().setRelyingPartyId(thirdParty.client.getClientId());
                    provider.getConfig().setRelyingPartySecret(thirdParty.client.getClientSecret());
                    provider.getConfig().setIssuer("http://" + thirdParty.zone.getIdentityZone().getSubdomain() + ".localhost:8080/uaa/oauth/token");
                    provider.getConfig().setResponseType("token id_token");
                    return provider;
                },
                (client) -> {
                    client.setScope(List.of("openid"));
                    client.setAuthorizedGrantTypes(List.of(TokenConstants.GRANT_TYPE_JWT_BEARER));
                    client.setAutoApproveScopes(List.of("openid"));
                    return client;
                },
                user -> null
        );

        //create foundation UAA
        AuthorizationServer workerServer = getAuthorizationServer(
                "worker",
                (provider) -> {
                    provider.setOriginKey(controlServer.zone.getIdentityZone().getSubdomain());
                    provider.getConfig().setLinkText("OIDC Provider: " + controlServer.zone.getIdentityZone().getSubdomain());
                    provider.getConfig().setTokenKey(getTokenVerificationKey(controlServer.zone.getIdentityZone()));
                    provider.getConfig().setRelyingPartyId(controlServer.client.getClientId());
                    provider.getConfig().setRelyingPartySecret(controlServer.client.getClientSecret());
                    provider.getConfig().setIssuer("http://" + controlServer.zone.getIdentityZone().getSubdomain() + ".localhost:8080/uaa/oauth/token");
                    provider.getConfig().setJwtClientAuthentication(true);
                    return provider;
                },
                (client) -> {
                    client.setScope(List.of("openid"));
                    client.setAuthorizedGrantTypes(List.of(TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE, GRANT_TYPE_REFRESH_TOKEN));
                    //TODO
                    JsonWebKeySet<JsonWebKey> jwkKeySet = new JsonWebKeySet<>(List.of(getJsonWebKey()));
                    ClientJwtConfiguration jwtConfiguration = new ClientJwtConfiguration(null, jwkKeySet);
                    client.setClientJwtConfig(JsonUtils.writeValueAsString(jwtConfiguration));
                    client.setAutoApproveScopes(List.of("openid"));
                    return client;
                },
                user -> null
        );

        //get an id_token from third party UAA
        String thirdPartyTokenResult = mockMvc.perform(
                        post("/oauth/token")
                                .header("Host", thirdParty.zone.getIdentityZone().getSubdomain() + ".localhost")
                                .param("client_id", thirdParty.client.getClientId())
                                .param("client_secret", thirdParty.client.getClientSecret())
                                .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                                .param("username", thirdParty.user.getUserName())
                                .param("password", thirdParty.user.getPassword())
                                .param("response_type", "token id_token refresh_token")
                                .accept(APPLICATION_JSON)
                                .contentType(APPLICATION_FORM_URLENCODED))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.id_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        Map<String, Object> thirdPartyTokens = JsonUtils.readValueAsMap(thirdPartyTokenResult);

        //do a JWT bearer grant on hub UAA, this results in id_token(hub)
        Map<String, Object> hubTokens = performJWTBearerGrantForJWT(
                controlServer.zone.getIdentityZone(),
                controlServer.client,
                (String) thirdPartyTokens.get("id_token")
        );


        return new ThreeWayUAASetup(thirdParty, thirdPartyTokens, controlServer, hubTokens, workerServer);
    }

    AuthorizationServer getAuthorizationServer(
            String identifier,
            Function<IdentityProvider<OIDCIdentityProviderDefinition>, IdentityProvider<OIDCIdentityProviderDefinition>> providerModifier,
            Function<UaaClientDetails, UaaClientDetails> clientModifier,
            Function<ScimUser, ScimUser> userModifier
    ) throws Exception {
        String subdomain = identifier + "-" + generator.generate();
        UaaClientDetails client = new UaaClientDetails(
                "client-" + subdomain,
                "",
                "openid",
                "password,refresh_token",
                null
        );
        client.setClientSecret(SECRET);
        client = clientModifier.apply(client);

        String userName = "user-" + subdomain;
        ScimUser user = new ScimUser(null, userName, "first" + identifier, "last" + identifier);
        user.setPassword(SECRET);
        user.setPrimaryEmail(userName + "@" + subdomain + ".org");
        user = userModifier.apply(user);

        MockMvcUtils.IdentityZoneCreationResult zone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                subdomain,
                mockMvc,
                webApplicationContext,
                client,
                false,
                null
        );

        if (user != null) {
            String password = user.getPassword();
            user = createUser(user, zone.getIdentityZone());
            user.setPassword(password);
        }

        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setAuthUrl(URI.create("http://myauthurl.com").toURL());
        definition.setTokenUrl(null);
        definition.setRelyingPartySecret(SECRET);
        definition.setLinkText("my oidc provider");
        definition.setResponseType("id_token");
        definition.addAttributeMapping("user_name", "user_name");
        IdentityProvider<OIDCIdentityProviderDefinition> provider = MultitenancyFixture.identityProvider(subdomain, zone.getIdentityZone().getId());
        provider.setType(OriginKeys.OIDC10);
        provider.setConfig(definition);
        provider = providerModifier.apply(provider);
        if (provider != null) {
            createOIDCProvider(zone.getIdentityZone(), provider);
        }

        return new AuthorizationServer(
                subdomain,
                zone,
                provider,
                client,
                user
        );
    }


    Map<String, Object> performJWTBearerGrantForJWT(IdentityZone theZone, ClientDetails client, String assertion) throws Exception {
        MockHttpServletRequestBuilder jwtBearerGrant = post("/oauth/token")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param("client_id", client.getClientId())
                .param("client_secret", client.getClientSecret())
                .param(GRANT_TYPE, GRANT_TYPE_JWT_BEARER)
                .param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.TokenFormat.JWT.getStringValue())
                .param("response_type", "id_token token")
                .param("scope", "openid")
                .param("assertion", assertion);
        if (hasText(theZone.getSubdomain())) {
            jwtBearerGrant = jwtBearerGrant.header("Host", theZone.getSubdomain() + ".localhost");
        }
        String tokenResponse = mockMvc.perform(jwtBearerGrant)
                .andDo(print())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return JsonUtils.readValueAsMap(tokenResponse);
    }

    ResultActions performTokenExchangeGrantForJWT(
            IdentityZone theZone,
            String subjectToken,
            String subjectTokenType,
            String requestTokenType,
            String audience,
            String scope,
            ClientDetails client,
            ClientAuthType clientAuthType,
            String responseTypes
    ) throws Exception {

        MockHttpServletRequestBuilder tokenExchange = post("/oauth/token")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(GRANT_TYPE, GRANT_TYPE_TOKEN_EXCHANGE)
                .param("scope", "openid")
                .param("subject_token", subjectToken)
                .param("subject_token_type", subjectTokenType)
                .param("requested_token_type", requestTokenType)
                .param("audience", audience)
                .param("scope", scope)
                .param("token_format", "jwt")
                ;
        switch (clientAuthType) {
            case BASIC -> {
                String authHeader = new String(Base64.encodeBase64((client.getClientId()+":"+client.getClientSecret()).getBytes()));
                tokenExchange = tokenExchange
                        .header("Authorization", "Basic " + authHeader)
                        .param("client_id", client.getClientId());
                break;
            }
            case FORM -> {
                tokenExchange = tokenExchange
                        .param("client_id", client.getClientId())
                        .param("client_secret", client.getClientSecret());
                break;
            }
            case CLIENT_ASSERTION -> {
                String clientAssertion = getClientAssertion(theZone, "http://some.url", (UaaClientDetails) client);
                tokenExchange = tokenExchange
                        .param("client_assertion", clientAssertion)
                        .param("client_assertion_type", JwtClientAuthentication.GRANT_TYPE);
                break;
            }
        }
        if (hasText(theZone.getSubdomain())) {
            tokenExchange = tokenExchange.header("Host", theZone.getSubdomain() + ".localhost");
        }
        if (hasText(responseTypes)) {
            tokenExchange = tokenExchange.param("response_type", responseTypes);
        }
        return mockMvc.perform(tokenExchange)
                .andDo(print());
    }

    KeyInfo getPrivateKey(String issuer) {
        return KeyInfoBuilder.build("id", SAMPLE_RSA_PRIVATE_KEY, issuer);
    }
    JsonWebKey getJsonWebKey() {
        String ISSUER = "http://localhost:8080/uaa/oauth/token";

        return new JsonWebKey(getPrivateKey(ISSUER).getJwkMap()).setKid("id");
    }

    String getClientAssertion(IdentityZone zone, String issuer, UaaClientDetails client) {
        String sub = client.getClientId();
        String audience = "http://" + zone.getSubdomain() + ".localhost:8080/uaa/oauth/token";
        ClientJwtConfiguration clientJwtConfiguration = JsonUtils.readValue(
                client.getClientJwtConfig(),
                ClientJwtConfiguration.class
        );
        Claims claims = new Claims();
        claims.setAud(Collections.singletonList(audience));
        claims.setSub(sub);
        claims.setIss(sub);
        claims.setJti(UUID.randomUUID().toString().replace("-", ""));
        claims.setIat((int) Instant.now().minusSeconds(120).getEpochSecond());
        claims.setExp(Instant.now().plusSeconds(300).getEpochSecond());
        JsonWebKey jsonWebKey = clientJwtConfiguration.getJwkSet().getKeys().get(0);
        KeyInfo signingKeyInfo = getPrivateKey(issuer);
        return signingKeyInfo.verifierCertificate().isPresent() ?
                JwtHelper.encodePlusX5t(claims.getClaimMap(), signingKeyInfo, signingKeyInfo.verifierCertificate().orElseThrow()).getEncoded() :
                JwtHelper.encode(claims.getClaimMap(), signingKeyInfo).getEncoded();

    }
}
