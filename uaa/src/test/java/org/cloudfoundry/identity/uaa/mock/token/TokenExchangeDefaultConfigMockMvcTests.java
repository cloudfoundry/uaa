package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.ResultActions;

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

public class TokenExchangeDefaultConfigMockMvcTests extends TokenExchangeMockMvcBase {


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

        assertThat(tokens.get(ISSUED_TOKEN_TYPE)).isEqualTo(TOKEN_TYPE_ACCESS);
        assertThat(tokens.get(TOKEN_TYPE)).isEqualTo(BEARER_TYPE.toLowerCase());

        Jwt tokenClaims = JwtHelper.decode((String) tokens.get("id_token"));
        Map<String, Object> claims = JsonUtils.readValueAsMap(tokenClaims.getClaims());

        assertThat(claims.get("user_name")).isEqualTo(thirdParty.user().getUserName());
        assertThat(claims.get("email")).isEqualTo(thirdParty.user().getEmails().get(0).getValue());
        assertThat(claims.get("origin")).isEqualTo(workerServer.identityProvider().getOriginKey());

        Map<String, Object> act = (Map<String, Object>) claims.get("act");
        assertThat(act).isNotNull();
        assertThat(act).isNotEmpty();
        Map<String, Object> controlServerClaims = JsonUtils.readValueAsMap(
                multiAuthSetup.getTokenClaims(
                        (String)multiAuthSetup.controlServerTokens().get("id_token"),
                "id_token",
                "controlServer"
                ).getClaims()
        );
        assertThat(act.get("sub")).isEqualTo(controlServerClaims.get("sub"));
        assertThat(act.get("iss")).isEqualTo(controlServerClaims.get("iss"));
        assertThat(act.get("client_id")).isEqualTo(workerServer.client().getClientId());
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

        assertThat(tokens.get(ISSUED_TOKEN_TYPE)).isEqualTo(TOKEN_TYPE_ACCESS);
        assertThat(tokens.get(TOKEN_TYPE)).isEqualTo(BEARER_TYPE.toLowerCase());

        Jwt tokenClaims = JwtHelper.decode((String) tokens.get("access_token"));
        Map<String, Object> claims = JsonUtils.readValueAsMap(tokenClaims.getClaims());

        assertThat(claims.get("user_name")).isEqualTo(thirdParty.user().getUserName());
        assertThat(claims.get("email")).isEqualTo(thirdParty.user().getEmails().get(0).getValue());
        assertThat(claims.get("origin")).isEqualTo(workerServer.identityProvider().getOriginKey());
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

        assertThat(tokens.get(ISSUED_TOKEN_TYPE)).isEqualTo(TOKEN_TYPE_ACCESS);
        assertThat(tokens.get(TOKEN_TYPE)).isEqualTo(BEARER_TYPE.toLowerCase());

        Jwt tokenClaims = JwtHelper.decode((String) tokens.get("access_token"));
        Map<String, Object> claims = JsonUtils.readValueAsMap(tokenClaims.getClaims());

        assertThat(claims.get("user_name")).isEqualTo(thirdParty.user().getUserName());
        assertThat(claims.get("email")).isEqualTo(thirdParty.user().getEmails().get(0).getValue());
        assertThat(claims.get("origin")).isEqualTo(workerServer.identityProvider().getOriginKey());

        Map<String, Object> subjectTokenClaims = JsonUtils.readValueAsMap(JwtHelper.decode(idToken).getClaims());
        Map<String, Object> actClaim = (Map<String, Object>) claims.get(ClaimConstants.ACT);
        assertThat(actClaim.get(ClaimConstants.CLIENT_ID)).isEqualTo(workerServer.client().getClientId());
        assertThat(actClaim.get(ClaimConstants.SUB)).isEqualTo(subjectTokenClaims.get(ClaimConstants.SUB));
        assertThat(actClaim.get(ClaimConstants.USER_NAME)).isEqualTo(subjectTokenClaims.get(ClaimConstants.USER_NAME));
        assertThat(actClaim.get(ClaimConstants.USER_ID)).isEqualTo(subjectTokenClaims.get(ClaimConstants.USER_ID));
        assertThat(actClaim.get(ClaimConstants.ORIGIN)).isEqualTo(subjectTokenClaims.get(ClaimConstants.ORIGIN));
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

        assertThat(claims.get("user_name")).isEqualTo(thirdParty.user().getUserName());
        assertThat(claims.get("email")).isEqualTo(thirdParty.user().getEmails().get(0).getValue());
        assertThat(claims.get("origin")).isEqualTo(workerServer.identityProvider().getOriginKey());
        assertThat(claims.get("client_id")).isEqualTo(audience.getClientId());
        assertThat(claims.get("cid")).isEqualTo(audience.getClientId());

        Map<String, Object> subjectTokenClaims = JsonUtils.readValueAsMap(JwtHelper.decode(accessToken).getClaims());
        Map<String, Object> actClaim = (Map<String, Object>) claims.get(ClaimConstants.ACT);
        assertThat(actClaim.get(ClaimConstants.CLIENT_ID)).isEqualTo(workerServer.client().getClientId());
        assertThat(actClaim.get(ClaimConstants.SUB)).isEqualTo(subjectTokenClaims.get(ClaimConstants.SUB));
        assertThat(actClaim.get(ClaimConstants.USER_NAME)).isEqualTo(subjectTokenClaims.get(ClaimConstants.USER_NAME));
        assertThat(actClaim.get(ClaimConstants.USER_ID)).isEqualTo(subjectTokenClaims.get(ClaimConstants.USER_ID));
        assertThat(actClaim.get(ClaimConstants.ORIGIN)).isEqualTo(subjectTokenClaims.get(ClaimConstants.ORIGIN));

    }

}
