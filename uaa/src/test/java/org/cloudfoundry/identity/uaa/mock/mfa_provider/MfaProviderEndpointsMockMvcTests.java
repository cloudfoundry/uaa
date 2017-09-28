package org.cloudfoundry.identity.uaa.mock.mfa_provider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cloudfoundry.identity.uaa.mfa_provider.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa_provider.JdbcMfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

public class MfaProviderEndpointsMockMvcTests extends InjectedMockContextTest {

    String adminToken;
    MfaProviderProvisioning mfaProviderProvisioning;
    @Before
    public void setup() throws Exception{
        mfaProviderProvisioning = getWebApplicationContext().getBean(JdbcMfaProviderProvisioning.class);
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret clients.admin uaa.admin");
    }

    @Test
    public void testCreateGoogleMfaProvider() throws Exception {
        MfaProvider mfaProvider = constructGoogleProvider();
        ((GoogleMfaProviderConfig)mfaProvider.getConfig())
                .setAlgorithm(GoogleMfaProviderConfig.Algorithm.SHA512)
                .setDigits(25)
                .setDuration(10);
        MvcResult mfaResponse = getMockMvc().perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();
        assertEquals(HttpStatus.CREATED.value(), mfaResponse.getResponse().getStatus());
        MfaProvider<GoogleMfaProviderConfig> mfaProviderCreated = JsonUtils.readValue(mfaResponse.getResponse().getContentAsString(), MfaProvider.class);
        assertEquals(IdentityZoneHolder.get().getName(), mfaProviderCreated.getConfig().getIssuer());
        assertEquals(IdentityZoneHolder.get().getId(), mfaProviderCreated.getIdentityZoneId());

    }
    
    @Test
    public void testCreateGoogleMfaProvider_UnauthorizedResponse() throws Exception{
        MfaProvider mfaProvider = constructGoogleProvider();
        ((GoogleMfaProviderConfig)mfaProvider.getConfig())
            .setAlgorithm(GoogleMfaProviderConfig.Algorithm.SHA512)
            .setDigits(25)
            .setDuration(10);
        String unauthorizedToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
            "clients.read clients.write clients.secret clients.admin");
        MvcResult mfaResponse = getMockMvc().perform(
            post("/mfa-providers")
                .header("Authorization", "Bearer " + unauthorizedToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();
        assertEquals(HttpStatus.FORBIDDEN.value(), mfaResponse.getResponse().getStatus());
        JsonNode json = JsonUtils.readTree(mfaResponse.getResponse().getContentAsString());
        assertNotNull("response was not json",json);
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
        assertEquals(HttpStatus.CREATED.value(), mfaResponse.getResponse().getStatus());
        MfaProvider<GoogleMfaProviderConfig> mfaProviderCreated = JsonUtils.readValue(mfaResponse.getResponse().getContentAsString(), MfaProvider.class);
        assertEquals(IdentityZoneHolder.get().getName(), mfaProviderCreated.getConfig().getIssuer());
        assertEquals(IdentityZoneHolder.get().getId(), mfaProviderCreated.getIdentityZoneId());

    }

    @Test
    public void testCreateGoogleMfaProviderInvalidType() throws Exception {
        MfaProvider mfaProvider = constructGoogleProvider();
        ObjectNode mfaAsJSON = (ObjectNode) JsonUtils.readTree(JsonUtils.writeValueAsString(mfaProvider));
        mfaAsJSON.put("type", "not-google-authenticator");
        MockHttpServletResponse response = getMockMvc().perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaAsJSON))).andReturn().getResponse();
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY.value(), response.getStatus());
        assertThat(response.getContentAsString(), Matchers.containsString("Provider type is required. Must be one of " + MfaProvider.MfaProviderType.getStringValues()));
    }

    @Test
    public void testCreateGoogleMfaProviderConfig() throws Exception {
        MfaProvider mfaProvider = constructGoogleProvider();
        ((GoogleMfaProviderConfig) mfaProvider.getConfig()).setDigits(-1);
        ObjectNode mfaAsJSON = (ObjectNode) JsonUtils.readTree(JsonUtils.writeValueAsString(mfaProvider));
        MockHttpServletResponse response = getMockMvc().perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaAsJSON))).andReturn().getResponse();
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY.value(), response.getStatus());
        assertThat(response.getContentAsString(), Matchers.containsString("Invalid Config for MFA Provider. Digits must be greater than 0"));
    }

    @Test
    public void testCreateGoogleMfaProviderConfigAlgorithm() throws Exception {
        MfaProvider mfaProvider = constructGoogleProvider();
        ObjectNode mfaAsJSON = (ObjectNode) JsonUtils.readTree(JsonUtils.writeValueAsString(mfaProvider));
        JsonNode configNode = mfaAsJSON.get("config");
        ((ObjectNode)configNode).put("algorithm", "SHA100");
        mfaAsJSON.set("config", configNode);

        MockHttpServletResponse response = getMockMvc().perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaAsJSON))).andReturn().getResponse();
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY.value(), response.getStatus());
        assertThat(response.getContentAsString(), Matchers.containsString("Invalid Config for MFA Provider. Algorithm must be one of " + GoogleMfaProviderConfig.Algorithm.getStringaValues()));
    }


    @Test
    public void testRetrieveMfaProviders() throws Exception {
        int mfaProvidersCount = mfaProviderProvisioning.retrieveAll(IdentityZoneHolder.get().getId()).size();
        MvcResult authorization = getMockMvc().perform(
                get("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)).andReturn();

        Assert.assertEquals(HttpStatus.OK.value(), authorization.getResponse().getStatus());
        List<MfaProvider> mfaProviders = JsonUtils.readValue(authorization.getResponse().getContentAsString(), List.class);
        Assert.assertEquals(mfaProvidersCount, mfaProviders.size());
    }

    @Test
    public void testRetrieveMfaProviderById() throws Exception {
        MfaProvider<GoogleMfaProviderConfig> createdProvider = constructGoogleProvider();
        createdProvider.setIdentityZoneId(IdentityZoneHolder.get().getId());
        createdProvider = mfaProviderProvisioning.create(createdProvider, IdentityZoneHolder.get().getId());
        MvcResult result = getMockMvc().perform(
                get("/mfa-providers/" + createdProvider.getId())
                        .header("Authorization", "Bearer " + adminToken)).andReturn();

        Assert.assertEquals(HttpStatus.OK.value(), result.getResponse().getStatus());
        Assert.assertEquals(JsonUtils.writeValueAsString(createdProvider), result.getResponse().getContentAsString());
    }

    @Test
    public void testCreateMfaForOtherZone() throws Exception{
        IdentityZone identityZone = MockMvcUtils.utils().createZoneUsingWebRequest(getMockMvc(), adminToken);

        MfaProvider mfaProvider = constructGoogleProvider();
        MvcResult mfaResponse = getMockMvc().perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();
        Assert.assertEquals(HttpStatus.CREATED.value(), mfaResponse.getResponse().getStatus());
    }

    @Test
    public void testGetMfaInOtherZone() throws Exception{
        IdentityZone identityZone = MockMvcUtils.utils().createZoneUsingWebRequest(getMockMvc(), adminToken);

        MfaProvider mfaProvider = constructGoogleProvider();
        MvcResult createResult = getMockMvc().perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();
        mfaProvider = JsonUtils.readValue(createResult.getResponse().getContentAsString(), MfaProvider.class);


        MvcResult mfaListResult = getMockMvc().perform(
                get("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())).andReturn();
        List<Map> mfaProviders = JsonUtils.readValue(mfaListResult.getResponse().getContentAsString(), List.class);
        List providerIds = mfaProviders.stream().map(provider -> provider.get("id")).collect(Collectors.toList());
        assertTrue(providerIds.contains(mfaProvider.getId()));
    }

    @Test
    public void testRetrieveMfaProviderByIdInvalid() throws Exception {
        MvcResult authorization = getMockMvc().perform(
                get("/mfa-providers/abcd")
                        .header("Authorization", "Bearer " + adminToken)).andReturn();

        Assert.assertEquals(HttpStatus.NOT_FOUND.value(), authorization.getResponse().getStatus());
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