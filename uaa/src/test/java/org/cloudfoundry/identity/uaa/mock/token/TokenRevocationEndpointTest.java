package org.cloudfoundry.identity.uaa.mock.token;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUserOAuthAccessToken;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.fail;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class TokenRevocationEndpointTest extends AbstractTokenMockMvcTests {
    protected RandomValueStringGenerator generator = new RandomValueStringGenerator();

    @Test
    public void revokeOwnJWToken() throws Exception {
        IdentityZone defaultZone = identityZoneProvisioning.retrieve(IdentityZone.getUaa().getId());
        defaultZone.getConfig().getTokenPolicy().setJwtRevocable(true);
        identityZoneProvisioning.update(defaultZone);

        try {
            BaseClientDetails client = setUpClients(
                    generator.generate(),
                    "clients.write",
                    "openid",
                    "client_credentials,password"
                    ,true
            );


            //this is the token we will revoke
            String clientToken =
                    getClientCredentialsOAuthAccessToken(
                            getMockMvc(),
                            client.getClientId(),
                            SECRET,
                            null,
                            null
                    );

            Jwt jwt = JwtHelper.decode(clientToken);
            Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {
            });
            String jti = (String) claims.get("jti");

            getMockMvc().perform(delete("/oauth/token/revoke/" + jti)
                    .header("Authorization", "Bearer " + clientToken))
                    .andExpect(status().isOk());

            tokenProvisioning.retrieve(jti, IdentityZoneHolder.get().getId());
        } catch (EmptyResultDataAccessException e) {
        } finally {
            defaultZone.getConfig().getTokenPolicy().setJwtRevocable(false);
            identityZoneProvisioning.update(defaultZone);
        }
    }

    @Test
    public void revokeOtherClientToken() throws Exception {
        String resourceClientId = generator.generate();

        BaseClientDetails client =
                setUpClients(resourceClientId,
                        "tokens.revoke",
                        "openid",
                        "client_credentials,password",
                        true
                );


        //this is the token we will revoke
        String revokeAccessToken =
                getClientCredentialsOAuthAccessToken(
                        getMockMvc(),
                        client.getClientId(),
                        SECRET,
                        "tokens.revoke",
                        null,
                        false
                );

        String tokenToBeRevoked =
                getClientCredentialsOAuthAccessToken(
                        getMockMvc(),
                        resourceClientId,
                        SECRET,
                        null,
                        null,
                        true
                );

        getMockMvc().perform(delete("/oauth/token/revoke/" + tokenToBeRevoked)
                .header("Authorization", "Bearer " + revokeAccessToken))
                .andExpect(status().isOk());


        try {
            tokenProvisioning.retrieve(tokenToBeRevoked, IdentityZoneHolder.get().getId());
            fail("Token should have been deleted");
        } catch (EmptyResultDataAccessException e) {
            //expected
        }
    }

    @Test
    public void revokeOtherClientTokenForbidden() throws Exception {
        String resourceClientId = generator.generate();
        BaseClientDetails resourceClient = setUpClients(
                resourceClientId,
                "uaa.resource",
                "uaa.resource",
                "client_credentials,password",
                true
        ) ;

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
                        getMockMvc(),
                        client.getClientId(),
                        SECRET,
                        null,
                        null,
                        false
                );

        String tokenToBeRevoked =
                getClientCredentialsOAuthAccessToken(
                        getMockMvc(),
                        resourceClientId,
                        SECRET,
                        null,
                        null,
                        true
                );

        getMockMvc().perform(delete("/oauth/token/revoke/" + tokenToBeRevoked)
                .header("Authorization", "Bearer " + revokeAccessToken))
                .andExpect(status().isForbidden());
    }

    @Test
    public void revokeOpaqueTokenWithOpaqueToken() throws Exception {
        ScimUser scimUser = setUpUser("testUser" + generator.generate());

        String opaqueUserToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", scimUser.getUserName(), "secret", null);

        getMockMvc().perform(delete("/oauth/token/revoke/" + opaqueUserToken)
                .header("Authorization", "Bearer " + opaqueUserToken))
                .andExpect(status().isOk());

        try {
            tokenProvisioning.retrieve(opaqueUserToken, IdentityZoneHolder.get().getId());
        } catch (EmptyResultDataAccessException e) {
        }
    }

    @Test
    public void test_Revoke_Client_And_User_Tokens() throws Exception {
        BaseClientDetails client = getAClientWithClientsRead();
        BaseClientDetails otherClient = getAClientWithClientsRead();

        //this is the token we will revoke
        String readClientsToken =
                getClientCredentialsOAuthAccessToken(
                        getMockMvc(),
                        client.getClientId(),
                        client.getClientSecret(),
                        null,
                        null
                );

        //this is the token from another client
        String otherReadClientsToken =
                getClientCredentialsOAuthAccessToken(
                        getMockMvc(),
                        otherClient.getClientId(),
                        otherClient.getClientSecret(),
                        null,
                        null
                );

        //ensure our token works
        getMockMvc().perform(
                get("/oauth/clients")
                        .header("Authorization", "Bearer "+readClientsToken)
        ).andExpect(status().isOk());

        //ensure we can't get to the endpoint without authentication
        getMockMvc().perform(
                get("/oauth/token/revoke/client/"+client.getClientId())
        ).andExpect(status().isUnauthorized());

        //ensure we can't get to the endpoint without correct scope
        getMockMvc().perform(
                get("/oauth/token/revoke/client/"+client.getClientId())
                        .header("Authorization", "Bearer "+otherReadClientsToken)
        ).andExpect(status().isForbidden());

        //ensure that we have the correct error for invalid client id
        getMockMvc().perform(
                get("/oauth/token/revoke/client/notfound"+ generator.generate())
                        .header("Authorization", "Bearer "+adminToken)
        ).andExpect(status().isNotFound());

        //we revoke the tokens for that client
        getMockMvc().perform(
                get("/oauth/token/revoke/client/"+client.getClientId())
                        .header("Authorization", "Bearer "+adminToken)
        ).andExpect(status().isOk());

        //we should fail attempting to use the token
        getMockMvc().perform(
                get("/oauth/clients")
                        .header("Authorization", "Bearer "+readClientsToken)
        )
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));

        ScimUser user = setUpUser(generator.generate().toLowerCase()+"@test.org");
        user.setPassword("secret");

        String userInfoToken = getUserOAuthAccessToken(
                getMockMvc(),
                client.getClientId(),
                client.getClientSecret(),
                user.getUserName(),
                user.getPassword(),
                "openid"
        );

        //ensure our token works
        getMockMvc().perform(
                get("/userinfo")
                        .header("Authorization", "Bearer "+userInfoToken)
        ).andExpect(status().isOk());

        //we revoke the tokens for that user
        getMockMvc().perform(
                get("/oauth/token/revoke/user/"+user.getId()+"notfound")
                        .header("Authorization", "Bearer "+adminToken)
        ).andExpect(status().isNotFound());


        //we revoke the tokens for that user
        getMockMvc().perform(
                get("/oauth/token/revoke/user/"+user.getId())
                        .header("Authorization", "Bearer "+adminToken)
        ).andExpect(status().isOk());

        getMockMvc().perform(
                get("/userinfo")
                        .header("Authorization", "Bearer "+userInfoToken)
        )
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(containsString("\"error\":\"invalid_token\"")));


    }

    protected BaseClientDetails getAClientWithClientsRead() throws Exception {
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
        scimUser.setEmails(Arrays.asList(email));
        scimUser.setOrigin(OriginKeys.UAA);
        return jdbcScimUserProvisioning.createUser(scimUser, "secret", IdentityZoneHolder.get().getId());
    }
}
