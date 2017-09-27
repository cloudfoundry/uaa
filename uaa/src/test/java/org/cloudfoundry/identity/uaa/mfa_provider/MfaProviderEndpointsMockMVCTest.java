package org.cloudfoundry.identity.uaa.mfa_provider;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;

public class MfaProviderEndpointsMockMVCTest extends InjectedMockContextTest {

    String adminToken;
    @Before
    public void setup() throws Exception{
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret clients.admin uaa.admin");
    }

    @Test
    public void testCreateGoogleMfaProviderConfigDefaults() throws Exception {
        MfaProvider mfaProvider = constructGoogleProvider();
        mfaProvider.setConfig(null);
        MvcResult mfaResponse = getMockMvc().perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();
        Assert.assertEquals(HttpStatus.CREATED.value(), mfaResponse.getResponse().getStatus());
        MfaProvider<GoogleMfaProviderConfig> mfaProviderCreated = JsonUtils.readValue(mfaResponse.getResponse().getContentAsString(), MfaProvider.class);
        Assert.assertEquals(IdentityZoneHolder.get().getName(), mfaProviderCreated.getConfig().getIssuer());
        Assert.assertEquals(IdentityZoneHolder.get().getId(), mfaProviderCreated.getIdentityZoneId());

    }

    @Test
    public void testCreateGoogleMfaProviderInvalidType() throws Exception {
        MfaProvider mfaProvider = constructGoogleProvider();
        ObjectNode mfaAsJSON = (ObjectNode) JsonUtils.readTree(JsonUtils.writeValueAsString(mfaProvider));
        mfaAsJSON.put("type", "not-google-authenticator");
        ResultActions authorization = getMockMvc().perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaAsJSON)));
        Assert.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY.value(), authorization.andReturn().getResponse().getStatus());
    }

    private MfaProvider<GoogleMfaProviderConfig> constructGoogleProvider() {
        MfaProvider<GoogleMfaProviderConfig> res = new MfaProvider();
        res.setName(new RandomValueStringGenerator(5).generate());
        res.setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);
        res.setConfig(constructGoogleProviderConfiguration());
        return res;
    }

    private GoogleMfaProviderConfig constructGoogleProviderConfiguration() {
        return new GoogleMfaProviderConfig().setAlgorithm(GoogleMfaProviderConfig.Algorithm.SHA256);
    }
}