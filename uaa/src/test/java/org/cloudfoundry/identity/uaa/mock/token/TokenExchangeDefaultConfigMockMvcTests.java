package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.ResultActions;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.BEARER_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.TOKEN_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.ISSUED_TOKEN_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_EXCHANGE_IMPERSONATE_CLIENT_PERMISSION;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ACCESS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ID;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class TokenExchangeDefaultConfigMockMvcTests extends TokenExchangeMockMvcBase {


    @Test
    void token_exchange_three_idps_using_id_token() throws Exception {

        ThreeWayUAASetup multiAuthSetup = getThreeWayUaaSetUp();
        AuthorizationServer thirdParty = multiAuthSetup.thirdPartyIdp();
        AuthorizationServer workerServer = multiAuthSetup.workerServer();

        //use the id_token(hub) to make a token-exchange on foundation-uaa
        String idToken = (String) multiAuthSetup.controlServerTokens().get("id_token");
        String tokenType = TOKEN_TYPE_ID;
        String requestTokenType = TOKEN_TYPE_ACCESS;
        String audience = null;
        String scope = null;

        ResultActions tokenExchangeResult = performTokenExchangeGrantForJWT(
                workerServer.zone().getIdentityZone(),
                idToken,
                tokenType,
                requestTokenType,
                audience,
                scope,
                workerServer.client(),
                ClientAuthType.FORM,
                "token id_token"
        );

        tokenExchangeResult
                .andExpect(status().isOk())
                .andExpect(jsonPath(".access_token").isNotEmpty())
                .andExpect(jsonPath(".id_token").isNotEmpty())
                .andExpect(jsonPath(".refresh_token").isNotEmpty());
        Map<String, Object> tokens = JsonUtils.readValueAsMap(tokenExchangeResult.andReturn().getResponse().getContentAsString());

        assertThat(tokens).containsEntry(ISSUED_TOKEN_TYPE, TOKEN_TYPE_ACCESS)
                .containsEntry(TOKEN_TYPE, BEARER_TYPE.toLowerCase());

        Jwt tokenClaims = JwtHelper.decode((String) tokens.get("id_token"));
        Map<String, Object> claims = JsonUtils.readValueAsMap(tokenClaims.getClaims());

        assertThat(claims).containsEntry("user_name", thirdParty.user().getUserName())
                .containsEntry("email", thirdParty.user().getEmails().getFirst().getValue())
                .containsEntry("origin", workerServer.identityProvider().getOriginKey());

        Map<String, Object> act = (Map<String, Object>) claims.get("act");
        assertThat(act).isNotEmpty();
        Map<String, Object> controlServerClaims = JsonUtils.readValueAsMap(
                multiAuthSetup.getTokenClaims(
                        (String) multiAuthSetup.controlServerTokens().get("id_token"),
                        "id_token",
                        "controlServer"
                ).getClaims()
        );
        assertThat(act).containsEntry("sub", controlServerClaims.get("sub"))
                .containsEntry("iss", controlServerClaims.get("iss"))
                .containsEntry("client_id", workerServer.client().getClientId());
    }

    @Test
    void token_exchange_three_idps_using_access_token() throws Exception {

        ThreeWayUAASetup multiAuthSetup = getThreeWayUaaSetUp();
        AuthorizationServer thirdParty = multiAuthSetup.thirdPartyIdp();
        AuthorizationServer workerServer = multiAuthSetup.workerServer();

        //use the id_token(hub) to make a token-exchange on foundation-uaa
        String accessToken = (String) multiAuthSetup.controlServerTokens().get("access_token");
        String tokenType = TOKEN_TYPE_ACCESS;
        String requestTokenType = TOKEN_TYPE_ACCESS;
        String audience = null;
        String scope = null;

        ResultActions tokenExchangeResult = performTokenExchangeGrantForJWT(
                workerServer.zone().getIdentityZone(),
                accessToken,
                tokenType,
                requestTokenType,
                audience,
                scope,
                workerServer.client(),
                ClientAuthType.FORM,
                null
        );

        tokenExchangeResult
                .andExpect(status().isOk())
                .andExpect(jsonPath(".access_token").isNotEmpty());
        Map<String, Object> tokens = JsonUtils.readValueAsMap(tokenExchangeResult.andReturn().getResponse().getContentAsString());

        assertThat(tokens).containsEntry(ISSUED_TOKEN_TYPE, TOKEN_TYPE_ACCESS)
                .containsEntry(TOKEN_TYPE, BEARER_TYPE.toLowerCase());

        Jwt tokenClaims = JwtHelper.decode((String) tokens.get("access_token"));
        Map<String, Object> claims = JsonUtils.readValueAsMap(tokenClaims.getClaims());

        assertThat(claims).containsEntry("user_name", thirdParty.user().getUserName())
                .containsEntry("email", thirdParty.user().getEmails().getFirst().getValue())
                .containsEntry("origin", workerServer.identityProvider().getOriginKey());
    }

    @Test
    void token_exchange_three_idps_using_opaque_access_token() throws Exception {

        ThreeWayUAASetup multiAuthSetup = getThreeWayUaaSetUp();
        AuthorizationServer thirdParty = multiAuthSetup.thirdPartyIdp();
        AuthorizationServer workerServer = multiAuthSetup.workerServer();

        // First, perform a token exchange at the worker server zone requesting an opaque token.
        // This stores the opaque access token in the worker server's revocable token store.
        String controlServerAccessToken = (String) multiAuthSetup.controlServerTokens().get("access_token");
        ResultActions firstExchangeResult = performTokenExchangeGrant(
                workerServer.zone().getIdentityZone(),
                controlServerAccessToken,
                TOKEN_TYPE_ACCESS,
                TOKEN_TYPE_ACCESS,
                null,
                null,
                workerServer.client(),
                ClientAuthType.FORM,
                null,
                TokenConstants.TokenFormat.OPAQUE.getStringValue()
        );
        firstExchangeResult.andExpect(status().isOk());
        Map<String, Object> firstExchangeTokens = JsonUtils.readValueAsMap(firstExchangeResult.andReturn().getResponse().getContentAsString());
        String opaqueAccessToken = (String) firstExchangeTokens.get("access_token");

        // The opaque token must not be a JWT (no dots separating header.payload.signature)
        assertThat(opaqueAccessToken).doesNotContain(".");

        // Now use the opaque access token (stored in the worker zone) as subject_token
        // in a second token exchange – this exercises the opaque→JWT resolution path
        ResultActions tokenExchangeResult = performTokenExchangeGrantForJWT(
                workerServer.zone().getIdentityZone(),
                opaqueAccessToken,
                TOKEN_TYPE_ACCESS,
                TOKEN_TYPE_ACCESS,
                null,
                null,
                workerServer.client(),
                ClientAuthType.FORM,
                null
        );

        tokenExchangeResult
                .andExpect(status().isOk())
                .andExpect(jsonPath(".access_token").isNotEmpty());
        Map<String, Object> tokens = JsonUtils.readValueAsMap(tokenExchangeResult.andReturn().getResponse().getContentAsString());

        assertThat(tokens).containsEntry(ISSUED_TOKEN_TYPE, TOKEN_TYPE_ACCESS)
                .containsEntry(TOKEN_TYPE, BEARER_TYPE.toLowerCase());

        Jwt tokenClaims = JwtHelper.decode((String) tokens.get("access_token"));
        Map<String, Object> claims = JsonUtils.readValueAsMap(tokenClaims.getClaims());

        assertThat(claims).containsEntry("user_name", thirdParty.user().getUserName())
                .containsEntry("email", thirdParty.user().getEmails().getFirst().getValue())
                .containsEntry("origin", workerServer.identityProvider().getOriginKey());
    }

    @Test
    void token_exchange_unknown_opaque_access_token_returns_unauthorized() throws Exception {
        ThreeWayUAASetup multiAuthSetup = getThreeWayUaaSetUp();
        AuthorizationServer workerServer = multiAuthSetup.workerServer();

        String unknownOpaque = "deadbeefdeadbeefdeadbeefdeadbeef";

        ResultActions tokenExchangeResult = performTokenExchangeGrantForJWT(
                workerServer.zone().getIdentityZone(),
                unknownOpaque,
                TOKEN_TYPE_ACCESS,
                TOKEN_TYPE_ACCESS,
                null,
                null,
                workerServer.client(),
                ClientAuthType.FORM,
                null
        );

        // Opaque token is not in the revocable store; external user authentication fails before the grant runs,
        // so the token endpoint responds with 401 rather than 400 invalid_grant.
        tokenExchangeResult.andExpect(status().isUnauthorized());
    }

    @Test
    void token_exchange_three_idps_using_client_assertion() throws Exception {

        ThreeWayUAASetup multiAuthSetup = getThreeWayUaaSetUp();
        AuthorizationServer thirdParty = multiAuthSetup.thirdPartyIdp();
        AuthorizationServer workerServer = multiAuthSetup.workerServer();

        //use the id_token(hub) to make a token-exchange on foundation-uaa
        String idToken = (String) multiAuthSetup.controlServerTokens().get("id_token");
        String tokenType = TOKEN_TYPE_ACCESS;
        String requestTokenType = TOKEN_TYPE_ACCESS;
        String audience = null;
        String scope = null;

        ResultActions tokenExchangeResult = performTokenExchangeGrantForJWT(
                workerServer.zone().getIdentityZone(),
                idToken,
                tokenType,
                requestTokenType,
                audience,
                scope,
                workerServer.client(),
                ClientAuthType.CLIENT_ASSERTION,
                "token id_token"
        );

        tokenExchangeResult
                .andExpect(status().isOk())
                .andExpect(jsonPath(".access_token").isNotEmpty())
                .andExpect(jsonPath(".id_token").isNotEmpty())
                .andExpect(jsonPath(".refresh_token").isNotEmpty());
        Map<String, Object> tokens = JsonUtils.readValueAsMap(tokenExchangeResult.andReturn().getResponse().getContentAsString());

        assertThat(tokens).containsEntry(ISSUED_TOKEN_TYPE, TOKEN_TYPE_ACCESS)
                .containsEntry(TOKEN_TYPE, BEARER_TYPE.toLowerCase());

        Jwt tokenClaims = JwtHelper.decode((String) tokens.get("access_token"));
        Map<String, Object> claims = JsonUtils.readValueAsMap(tokenClaims.getClaims());

        assertThat(claims)
                .containsEntry("user_name", thirdParty.user().getUserName())
                .containsEntry("email", thirdParty.user().getEmails().getFirst().getValue())
                .containsEntry("origin", workerServer.identityProvider().getOriginKey());

        Map<String, Object> subjectTokenClaims = JsonUtils.readValueAsMap(JwtHelper.decode(idToken).getClaims());
        Map<String, Object> actClaim = (Map<String, Object>) claims.get(ClaimConstants.ACT);
        assertThat(actClaim)
                .containsEntry(ClaimConstants.CLIENT_ID, workerServer.client().getClientId())
                .containsEntry(ClaimConstants.SUB, subjectTokenClaims.get(ClaimConstants.SUB))
                .containsEntry(ClaimConstants.USER_NAME, subjectTokenClaims.get(ClaimConstants.USER_NAME))
                .containsEntry(ClaimConstants.USER_ID, subjectTokenClaims.get(ClaimConstants.USER_ID))
                .containsEntry(ClaimConstants.ORIGIN, subjectTokenClaims.get(ClaimConstants.ORIGIN));
    }

    /**
     * Confirms that a {@code subject_token} with a tampered payload is rejected in the
     * default configuration (no bean overrides).
     *
     * <p>Takes a legitimately signed access token from the control server, replaces its
     * {@code sub} and {@code user_id} claims, and submits the result as {@code subject_token}.
     * The {@code iss} claim is left intact so that the registered IdP can be resolved;
     * the signature is now cryptographically invalid for the modified payload.
     *
     * <p>The default {@code tokenExchangeAuthenticationManager} wraps
     * {@link org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager},
     * which resolves the IdP by the token's {@code iss} claim and then verifies the
     * signature against that IdP's published keys.  The mismatch is caught at the filter
     * layer, before {@code TokenExchangeGranter.getTokenActor()} is reached, and translated
     * to HTTP 401.
     */
    @Test
    void forged_subject_token_is_blocked_by_filter_in_default_configuration() throws Exception {
        ThreeWayUAASetup setup = getThreeWayUaaSetUp();
        AuthorizationServer workerServer = setup.workerServer();

        String legitimateJwt = (String) setup.controlServerTokens().get("access_token");

        // Tamper sub and user_id; leave iss intact so the registered IdP can be resolved.
        String[] parts = legitimateJwt.split("\\.");
        Map<String, Object> claims = JsonUtils.readValueAsMap(
                new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
        claims.put(ClaimConstants.SUB,     "FORGED-" + claims.get(ClaimConstants.SUB));
        claims.put(ClaimConstants.USER_ID, "FORGED-" + claims.get(ClaimConstants.USER_ID));
        String tamperedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(JsonUtils.writeValueAsString(claims).getBytes(StandardCharsets.UTF_8));

        // Original header · tampered payload · original signature (now invalid).
        String tamperedJwt = parts[0] + "." + tamperedPayload + "." + parts[2];

        ResultActions result = performTokenExchangeGrantForJWT(
                workerServer.zone().getIdentityZone(),
                tamperedJwt,
                TokenConstants.TOKEN_TYPE_ACCESS,
                TokenConstants.TOKEN_TYPE_ACCESS,
                null, null,
                workerServer.client(),
                ClientAuthType.FORM,
                null
        );

        // The filter's validateToken() catches the invalid signature → 401.
        result.andExpect(status().isUnauthorized());
    }

    @Test
    void token_exchange_impersonate_client() throws Exception {

        ThreeWayUAASetup multiAuthSetup = getThreeWayUaaSetUp();
        AuthorizationServer thirdParty = multiAuthSetup.thirdPartyIdp();
        AuthorizationServer workerServer = multiAuthSetup.workerServer();

        UaaClientDetails audience = new UaaClientDetails(
                "audienceClient-" + workerServer.zone().getIdentityZone().getSubdomain(),
                "",
                "openid,cloud_controller.read,cloud_controller.write,uaa.user",
                "password,refresh_token",
                null
        );
        audience.setAutoApproveScopes(audience.getScope());
        audience.setClientSecret(SECRET);
        webApplicationContext.getBean(MultitenantJdbcClientDetailsService.class).addClientDetails(
                audience,
                workerServer.zone().getIdentityZone().getId()
        );

        //update the worker server client to have `token_exchange.impersonate.<audience.getClientId()> authority
        String requiredImpersonationAuthority = String.format(TOKEN_EXCHANGE_IMPERSONATE_CLIENT_PERMISSION, audience.getClientId());
        UaaClientDetails workerClient = (UaaClientDetails) workerServer.client();
        workerClient.setAuthorities(List.of(new SimpleGrantedAuthority(requiredImpersonationAuthority)));
        webApplicationContext.getBean(MultitenantJdbcClientDetailsService.class).updateClientDetails(
                workerClient,
                workerServer.zone().getIdentityZone().getId()
        );

        //use the id_token(hub) to make a token-exchange on foundation-uaa
        String accessToken = (String) multiAuthSetup.controlServerTokens().get("access_token");
        String tokenType = TOKEN_TYPE_ACCESS;
        String scope = null;

        ResultActions tokenExchangeResult = performTokenExchangeGrantForJWT(
                workerServer.zone().getIdentityZone(),
                accessToken,
                tokenType,
                tokenType,
                audience.getClientId(),
                scope,
                workerServer.client(),
                ClientAuthType.FORM,
                null
        );

        tokenExchangeResult
                .andExpect(status().isOk())
                .andExpect(jsonPath(".access_token").isNotEmpty());
        Map<String, Object> tokens = JsonUtils.readValueAsMap(tokenExchangeResult.andReturn().getResponse().getContentAsString());

        Jwt tokenClaims = JwtHelper.decode((String) tokens.get("access_token"));
        Map<String, Object> claims = JsonUtils.readValueAsMap(tokenClaims.getClaims());

        assertThat(claims)
                .containsEntry("user_name", thirdParty.user().getUserName())
                .containsEntry("email", thirdParty.user().getEmails().getFirst().getValue())
                .containsEntry("origin", workerServer.identityProvider().getOriginKey())
                .containsEntry("client_id", audience.getClientId())
                .containsEntry("cid", audience.getClientId());

        Map<String, Object> subjectTokenClaims = JsonUtils.readValueAsMap(JwtHelper.decode(accessToken).getClaims());
        Map<String, Object> actClaim = (Map<String, Object>) claims.get(ClaimConstants.ACT);
        assertThat(actClaim)
                .containsEntry(ClaimConstants.CLIENT_ID, workerServer.client().getClientId())
                .containsEntry(ClaimConstants.SUB, subjectTokenClaims.get(ClaimConstants.SUB))
                .containsEntry(ClaimConstants.USER_NAME, subjectTokenClaims.get(ClaimConstants.USER_NAME))
                .containsEntry(ClaimConstants.USER_ID, subjectTokenClaims.get(ClaimConstants.USER_ID))
                .containsEntry(ClaimConstants.ORIGIN, subjectTokenClaims.get(ClaimConstants.ORIGIN));

    }

}
