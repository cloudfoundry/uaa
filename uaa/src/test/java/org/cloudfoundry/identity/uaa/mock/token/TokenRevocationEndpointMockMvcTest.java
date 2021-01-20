package org.cloudfoundry.identity.uaa.mock.token;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.event.TokenRevocationEvent;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.web.context.support.GenericWebApplicationContext;

import java.util.Collections;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUserOAuthAccessToken;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class TokenRevocationEndpointMockMvcTest extends AbstractTokenMockMvcTests {
    protected RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private TestApplicationEventListener<TokenRevocationEvent> tokenRevocationEventListener;

    @BeforeEach
    void setup() {
        tokenRevocationEventListener = MockMvcUtils.addEventListener((GenericWebApplicationContext) webApplicationContext, TokenRevocationEvent.class);
        tokenRevocationEventListener.clearEvents();
    }

    @Test
    void revokeOwnJWToken() throws Exception {
        IdentityZone defaultZone = identityZoneProvisioning.retrieve(IdentityZone.getUaaZoneId());
        defaultZone.getConfig().getTokenPolicy().setJwtRevocable(true);
        identityZoneProvisioning.update(defaultZone);

        try {
            BaseClientDetails client = setUpClients(
                    generator.generate(),
                    "clients.write",
                    "openid",
                    "client_credentials,password"
                    , true
            );


            //this is the token we will revoke
            String clientToken =
                    getClientCredentialsOAuthAccessToken(
                            mockMvc,
                            client.getClientId(),
                            SECRET,
                            null,
                            null
                    );

            Jwt jwt = JwtHelper.decode(clientToken);
            Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {
            });
            String jti = (String) claims.get("jti");

            assertEquals(0, tokenRevocationEventListener.getEventCount());
            mockMvc.perform(delete("/oauth/token/revoke/" + jti)
                    .header("Authorization", "Bearer " + clientToken))
                    .andExpect(status().isOk());

            assertEquals(1, tokenRevocationEventListener.getEventCount());
            TokenRevocationEvent tokenRevocationEvent = tokenRevocationEventListener.getEvents().get(0);
            assertEquals(client.getClientId(), tokenRevocationEvent.getClientId());
            assertNull(tokenRevocationEvent.getUserId());
            assertThat(tokenRevocationEvent.getAuditEvent().getData(), containsString(client.getClientId()));
            assertThat(tokenRevocationEvent.getAuditEvent().getData(), not(containsString("UserID")));
            assertThat(tokenRevocationEvent.getAuditEvent().getOrigin(), containsString(client.getClientId()));
            revocableTokenProvisioning.retrieve(jti, IdentityZoneHolder.get().getId());
            fail("Expected EmptyResultDataAccessException to be thrown for revoked token");
        } catch (EmptyResultDataAccessException ignored) {
        } finally {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(false);
            identityZoneProvisioning.update(defaultZone);
        }
    }

    @Test
    void revokeOtherClientTokenByJti() throws Exception {
        String revokerClientId = generator.generate();
        String resourceClientId = generator.generate();

        BaseClientDetails revokerClient =
                setUpClients(revokerClientId,
                        "tokens.revoke",
                        "openid",
                        "client_credentials,password",
                        true
                );


        BaseClientDetails targetClient =
                setUpClients(resourceClientId,
                        "uaa.none",
                        "openid",
                        "client_credentials,password",
                        true
                );


        //this is the token we will revoke
        String revokeAccessToken =
                getClientCredentialsOAuthAccessToken(
                        mockMvc,
                        revokerClient.getClientId(),
                        SECRET,
                        "tokens.revoke",
                        null,
                        false
                );

        String tokenToBeRevoked =
                getClientCredentialsOAuthAccessToken(
                        mockMvc,
                        resourceClientId,
                        SECRET,
                        null,
                        null,
                        true
                );

        mockMvc.perform(delete("/oauth/token/revoke/" + tokenToBeRevoked)
                .header("Authorization", "Bearer " + revokeAccessToken))
                .andExpect(status().isOk());


        try {
            revocableTokenProvisioning.retrieve(tokenToBeRevoked, IdentityZoneHolder.get().getId());
            fail("Token should have been deleted");
        } catch (EmptyResultDataAccessException e) {
            //expected
        }
    }

    @Test
    void revokeOtherClientTokenByClientId_tokensDotRevoke() throws Exception {
        revokeOtherClientTokenByClientId("tokens.revoke");
    }

    @Test
    void revokeOtherClientTokenByClientId_uaaDotAdmin() throws Exception {
        revokeOtherClientTokenByClientId("uaa.admin");
    }

    void revokeOtherClientTokenByClientId(String scope) throws Exception {
        String revokerClientId = generator.generate();
        String resourceClientId = generator.generate();

        BaseClientDetails revokerClient =
                setUpClients(revokerClientId,
                        scope,
                        "openid",
                        "client_credentials,password",
                        true
                );


        BaseClientDetails targetClient =
                setUpClients(resourceClientId,
                        "uaa.none",
                        "openid",
                        "client_credentials,password",
                        true
                );


        //this is the token we will revoke
        String revokeAccessToken =
                getClientCredentialsOAuthAccessToken(
                        mockMvc,
                        revokerClient.getClientId(),
                        SECRET,
                        scope,
                        null,
                        false
                );

        String tokenToBeRevoked =
                getClientCredentialsOAuthAccessToken(
                        mockMvc,
                        resourceClientId,
                        SECRET,
                        null,
                        null,
                        true
                );

        mockMvc.perform(delete("/oauth/token/revoke/client/" + resourceClientId)
                .header("Authorization", "Bearer " + revokeAccessToken))
                .andExpect(status().isOk());


        try {
            revocableTokenProvisioning.retrieve(tokenToBeRevoked, IdentityZoneHolder.get().getId());
            fail("Token should have been deleted");
        } catch (EmptyResultDataAccessException e) {
            //expected
        }
    }

    @Test
    void revokeOtherClientTokenForbidden() throws Exception {
        String resourceClientId = generator.generate();
        BaseClientDetails resourceClient = setUpClients(
                resourceClientId,
                "uaa.resource",
                "uaa.resource",
                "client_credentials,password",
                true
        );

        BaseClientDetails client = setUpClients(
                generator.generate(),
                "clients.write",
                "openid",
                "client_credentials,password",
                true
        );


        //this is the token we will revoke
        String revokeAccessToken =
                getClientCredentialsOAuthAccessToken(
                        mockMvc,
                        client.getClientId(),
                        SECRET,
                        null,
                        null,
                        false
                );

        String tokenToBeRevoked =
                getClientCredentialsOAuthAccessToken(
                        mockMvc,
                        resourceClientId,
                        SECRET,
                        null,
                        null,
                        true
                );

        mockMvc.perform(delete("/oauth/token/revoke/" + tokenToBeRevoked)
                .header("Authorization", "Bearer " + revokeAccessToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void revokeOpaqueTokenWithOpaqueToken() throws Exception {
        ScimUser scimUser = setUpUser("testUser" + generator.generate());

        String opaqueUserToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", scimUser.getUserName(), "secret", null);

        mockMvc.perform(delete("/oauth/token/revoke/" + opaqueUserToken)
                .header("Authorization", "Bearer " + opaqueUserToken))
                .andExpect(status().isOk());

        try {
            revocableTokenProvisioning.retrieve(opaqueUserToken, IdentityZoneHolder.get().getId());
        } catch (EmptyResultDataAccessException ignored) {
        }
    }

    @Test
    void test_Revoke_All_Client_Tokens() throws Exception {
        BaseClientDetails client = getAClientWithClientsRead();
        BaseClientDetails otherClient = getAClientWithClientsRead();

        //this is the token we will revoke
        String readClientsToken =
                getClientCredentialsOAuthAccessToken(
                        mockMvc,
                        client.getClientId(),
                        client.getClientSecret(),
                        null,
                        null
                );

        //this is the token from another client
        String otherReadClientsToken =
                getClientCredentialsOAuthAccessToken(
                        mockMvc,
                        otherClient.getClientId(),
                        otherClient.getClientSecret(),
                        null,
                        null
                );

        //ensure our token works
        mockMvc.perform(
                get("/oauth/clients")
                        .header("Authorization", "Bearer " + readClientsToken)
        ).andExpect(status().isOk());

        //ensure we can't get to the endpoint without authentication
        mockMvc.perform(
                get("/oauth/token/revoke/client/" + client.getClientId())
        ).andExpect(status().isUnauthorized());

        //ensure we can't get to the endpoint without correct scope
        mockMvc.perform(
                get("/oauth/token/revoke/client/" + client.getClientId())
                        .header("Authorization", "Bearer " + otherReadClientsToken)
        ).andExpect(status().isForbidden());

        //ensure that we have the correct error for invalid client id
        mockMvc.perform(
                get("/oauth/token/revoke/client/notfound" + generator.generate())
                        .header("Authorization", "Bearer " + adminToken)
        ).andExpect(status().isNotFound());

        assertEquals(0, tokenRevocationEventListener.getEventCount());
        //we revoke the tokens for that client
        mockMvc.perform(
                get("/oauth/token/revoke/client/" + client.getClientId())
                        .header("Authorization", "Bearer " + adminToken)
        ).andExpect(status().isOk());
        assertEquals(1, tokenRevocationEventListener.getEventCount());
        assertEquals(client.getClientId(), tokenRevocationEventListener.getEvents().get(0).getClientId());
        assertNull("Event for client based revocation should not contain userid", tokenRevocationEventListener.getEvents().get(0).getUserId());
        assertThat(tokenRevocationEventListener.getEvents().get(0).getAuditEvent().getData(), containsString(client.getClientId()));
        assertThat(tokenRevocationEventListener.getEvents().get(0).getAuditEvent().getData(), not(containsString("UserID")));
        assertThat(tokenRevocationEventListener.getEvents().get(0).getAuditEvent().getOrigin(), containsString("admin"));


        //we should fail attempting to use the token
        mockMvc.perform(
                get("/oauth/clients")
                        .header("Authorization", "Bearer " + readClientsToken)
        )
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));

    }

    @Test
    void test_Revoke_All_Tokens_For_User() throws Exception {
        BaseClientDetails client = getAClientWithClientsRead();

        ScimUser user = setUpUser(generator.generate().toLowerCase() + "@test.org");
        user.setPassword("secret");

        String userInfoToken = getUserOAuthAccessToken(
                mockMvc,
                client.getClientId(),
                client.getClientSecret(),
                user.getUserName(),
                user.getPassword(),
                "openid"
        );

        //ensure our token works
        mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "Bearer " + userInfoToken)
        ).andExpect(status().isOk());

        //we revoke the tokens for nonexistent user
        mockMvc.perform(
                get("/oauth/token/revoke/user/" + user.getId() + "notfound")
                        .header("Authorization", "Bearer " + adminToken)
        ).andExpect(status().isNotFound());

        assertEquals(0, tokenRevocationEventListener.getEventCount());

        //we revoke the tokens for that user
        mockMvc.perform(
                get("/oauth/token/revoke/user/" + user.getId())
                        .header("Authorization", "Bearer " + adminToken)
        ).andExpect(status().isOk());

        assertEquals(1, tokenRevocationEventListener.getEventCount());
        assertEquals(user.getId(), tokenRevocationEventListener.getEvents().get(0).getUserId());
        assertNull(tokenRevocationEventListener.getEvents().get(0).getClientId());
        assertThat(tokenRevocationEventListener.getEvents().get(0).getAuditEvent().getData(), containsString(user.getId()));
        assertThat(tokenRevocationEventListener.getEvents().get(0).getAuditEvent().getData(), not(containsString("ClientID")));
        assertThat(tokenRevocationEventListener.getEvents().get(0).getAuditEvent().getOrigin(), containsString("admin"));
        //should fail with 401
        mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "Bearer " + userInfoToken)
        )
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));
    }

    @Test
    void aUserCanRevokeTheirOwnToken() throws Exception {
        BaseClientDetails client = getAClientWithClientsRead();
        ScimUser user = setUpUser(generator.generate().toLowerCase() + "@test.org");
        user.setPassword("secret");

        String userInfoToken = getUserOAuthAccessToken(
                mockMvc,
                client.getClientId(),
                client.getClientSecret(),
                user.getUserName(),
                user.getPassword(),
                "openid"
        );

        //ensure our token works
        mockMvc.perform(
                get("/userinfo").header("Authorization", "Bearer " + userInfoToken)
        ).andExpect(status().isOk());

        //revoke our own token
        mockMvc.perform(
                get("/oauth/token/revoke/user/" + user.getId()).header("Authorization", "Bearer " + userInfoToken)
        ).andExpect(status().isOk());

        assertEquals(1, tokenRevocationEventListener.getEventCount());
        assertEquals(user.getId(), tokenRevocationEventListener.getEvents().get(0).getUserId());
        assertNull(tokenRevocationEventListener.getEvents().get(0).getClientId());
        assertThat(tokenRevocationEventListener.getEvents().get(0).getAuditEvent().getData(), containsString(user.getId()));
        assertThat(tokenRevocationEventListener.getEvents().get(0).getAuditEvent().getData(), not(containsString("ClientID")));
        assertThat(tokenRevocationEventListener.getEvents().get(0).getAuditEvent().getOrigin(), containsString(user.getUserName()));

        //should fail with 401
        mockMvc.perform(
                get("/userinfo").header("Authorization", "Bearer " + userInfoToken)
        )
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));
    }

    private void revokeUserClientCombinationTokenWithAuth() throws Exception {
        BaseClientDetails client = getAClientWithClientsRead();
        BaseClientDetails otherClient = getAClientWithClientsRead();
        IdentityZone zone = IdentityZoneHolder.get();

        ScimUser user1 = setUpUser(generator.generate().toLowerCase() + "@test.org");
        user1.setPassword("secret");

        ScimUser user2 = setUpUser(generator.generate().toLowerCase() + "@test.org");
        user2.setPassword("secret");

        //All three tokens should be revocable
        String client1UserToken = getUserOAuthAccessToken(
                mockMvc,
                client.getClientId(),
                client.getClientSecret(),
                user1.getUserName(),
                user1.getPassword(),
                "openid",
                zone,
                true
        );

        String client2UserToken = getUserOAuthAccessToken(
                mockMvc,
                otherClient.getClientId(),
                otherClient.getClientSecret(),
                user1.getUserName(),
                user1.getPassword(),
                "openid",
                zone,
                true
        );

        String client1DifferentUserToken = getUserOAuthAccessToken(
                mockMvc,
                client.getClientId(),
                client.getClientSecret(),
                user2.getUserName(),
                user2.getPassword(),
                "openid",
                zone,
                true
        );

        mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "Bearer " + client1UserToken)
        ).andExpect(status().isOk());

        mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "Bearer " + client2UserToken)
        ).andExpect(status().isOk());

        mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "Bearer " + client1DifferentUserToken)
        ).andExpect(status().isOk());

        assertEquals(0, tokenRevocationEventListener.getEventCount());
        //we revoke the tokens for that user
        mockMvc.perform(
                get("/oauth/token/revoke/user/" + user1.getId() + "/client/" + client.getClientId())
                        .header("Authorization", "Bearer " + adminToken)
        ).andExpect(status().isOk());

        assertEquals(1, tokenRevocationEventListener.getEventCount());
        assertEquals(client.getClientId(), tokenRevocationEventListener.getEvents().get(0).getClientId());
        assertEquals(user1.getId(), tokenRevocationEventListener.getEvents().get(0).getUserId());
        assertThat(tokenRevocationEventListener.getEvents().get(0).getAuditEvent().getData(), containsString(client.getClientId()));
        assertThat(tokenRevocationEventListener.getEvents().get(0).getAuditEvent().getData(), containsString(user1.getId()));
        assertThat(tokenRevocationEventListener.getEvents().get(0).getAuditEvent().getOrigin(), containsString("admin"));

        //should fail with 401
        mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "Bearer " + client1UserToken)
        )
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));


        // ensure tokens issued for user to other clients still work
        mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "Bearer " + client2UserToken)
        ).andExpect(status().isOk());

        // ensure tokens issued for client and other user still work
        mockMvc.perform(
                get("/userinfo")
                        .header("Authorization", "Bearer " + client1DifferentUserToken)
        ).andExpect(status().isOk());

    }

    @Test
    void test_Revoke_Client_User_Combination_Token() throws Exception {
        revokeUserClientCombinationTokenWithAuth();
    }

    @Test
    void test_Revoke_Client_User_Combination_Token_With_Revoke_Scope() throws Exception {
        String revokerClientId = generator.generate();
        BaseClientDetails revokerClient =
                setUpClients(revokerClientId,
                        "tokens.revoke",
                        "openid",
                        "client_credentials,password",
                        true
                );
        //this is the token we will revoke
        String revokeAccessToken =
                getClientCredentialsOAuthAccessToken(
                        mockMvc,
                        revokerClient.getClientId(),
                        SECRET,
                        "tokens.revoke",
                        null,
                        false
                );

        revokeUserClientCombinationTokenWithAuth();
    }

    private BaseClientDetails getAClientWithClientsRead() {
        BaseClientDetails client = setUpClients(
                generator.generate(),
                "clients.read",
                "openid",
                "client_credentials,password",
                true
        );
        client.setClientSecret("secret");
        return client;
    }

    private ScimUser setUpUser(String username) {
        ScimUser scimUser = new ScimUser();
        scimUser.setUserName(username);
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(username);
        scimUser.setEmails(Collections.singletonList(email));
        scimUser.setOrigin(OriginKeys.UAA);
        return jdbcScimUserProvisioning.createUser(scimUser, "secret", IdentityZoneHolder.get().getId());
    }
}
