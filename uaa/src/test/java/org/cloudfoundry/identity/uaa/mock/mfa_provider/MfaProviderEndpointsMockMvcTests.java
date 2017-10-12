package org.cloudfoundry.identity.uaa.mock.mfa_provider;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.mfa_provider.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa_provider.JdbcMfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class MfaProviderEndpointsMockMvcTests extends InjectedMockContextTest {

    String adminToken;
    String nonAdminToken;
    TestApplicationEventListener<EntityDeletedEvent> eventListener;

    MfaProviderProvisioning mfaProviderProvisioning;
    @Before
    public void setup() throws Exception{

        mfaProviderProvisioning = getWebApplicationContext().getBean(JdbcMfaProviderProvisioning.class);
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret clients.admin uaa.admin");
        nonAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write clients.admin");
        eventListener = MockMvcUtils.addEventListener(getWebApplicationContext(), EntityDeletedEvent.class);
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

    @Test
    public void testUpdateGoogleMfaProviderInvalidType() throws Exception {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleProvider();
        mfaProvider.setConfig(null);
        MvcResult mfaResponse = getMockMvc().perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();

        mfaProvider = JsonUtils.readValue(mfaResponse.getResponse().getContentAsString(), MfaProvider.class);

        ObjectNode mfaAsJSON = (ObjectNode) JsonUtils.readTree(JsonUtils.writeValueAsString(mfaProvider));
        mfaAsJSON.put("type", "not-google-authenticator");
        ResultActions authorization = getMockMvc().perform(
                put("/mfa-providers/" + mfaProvider.getId())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaAsJSON)));
        Assert.assertEquals(HttpStatus.UNPROCESSABLE_ENTITY.value(), authorization.andReturn().getResponse().getStatus());
    }

    @Test
    public void testUpdateNonExistent() throws Exception {
        getMockMvc().perform(put("/mfa-providers/invalid")
            .header("Authorization", "bearer " + adminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(new MfaProvider<>())))
                .andExpect(status().isNotFound());
    }

    @Test
    public void testUpdateForbiddenNonAdmin() throws Exception {
        getMockMvc().perform(put("/mfa-providers/invalid")
                .header("Authorization", "bearer " + nonAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(new MfaProvider<>())))
                .andExpect(status().isForbidden());
    }

    @Test
    public void testCreateAndUpdateMfaProvider() throws Exception {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleProvider();
        mfaProvider.setConfig(null);
        MvcResult mfaResponse = getMockMvc().perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();

        mfaProvider = JsonUtils.readValue(mfaResponse.getResponse().getContentAsString(), MfaProvider.class);

        mfaProvider.setName("UpdatedName");
        mfaProvider.getConfig().setDigits(13);

        MvcResult updateResponse = getMockMvc().perform(
                put("/mfa-providers/" + mfaProvider.getId())
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();

        MfaProvider<GoogleMfaProviderConfig> updatedProvider = JsonUtils.readValue(updateResponse.getResponse().getContentAsString(), MfaProvider.class);

        Assert.assertEquals(HttpStatus.OK.value(), updateResponse.getResponse().getStatus());
        Assert.assertEquals(13, updatedProvider.getConfig().getDigits());
        Assert.assertEquals("UpdatedName", updatedProvider.getName());

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
    public void testUpdateMfaForOtherZone() throws Exception{
        IdentityZone identityZone = MockMvcUtils.utils().createZoneUsingWebRequest(getMockMvc(), adminToken);

        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleProvider();
        MvcResult mfaResponse = getMockMvc().perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();
        Assert.assertEquals(HttpStatus.CREATED.value(), mfaResponse.getResponse().getStatus());

        mfaProvider = JsonUtils.readValue(mfaResponse.getResponse().getContentAsString(), MfaProvider.class);

        mfaProvider.setName("UpdatedName");
        mfaProvider.getConfig().setDigits(13);

        MvcResult updateResponse = getMockMvc().perform(
                put("/mfa-providers/" + mfaProvider.getId())
                        .header("Authorization", "Bearer " + adminToken)
                        .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();
        Assert.assertEquals(HttpStatus.OK.value(), updateResponse.getResponse().getStatus());

        MfaProvider<GoogleMfaProviderConfig> updatedProvider = JsonUtils.readValue(updateResponse.getResponse().getContentAsString(), MfaProvider.class);
        Assert.assertEquals(13, updatedProvider.getConfig().getDigits());
        Assert.assertEquals("UpdatedName", updatedProvider.getName());

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

    @Test
    public void testDeleteMfaProvider() throws Exception {
        MfaProvider provider = constructGoogleProvider();
        MockHttpServletResponse createResponse = getMockMvc().perform(post("/mfa-providers")
            .header("Authorization", "Bearer " + adminToken)
            .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(provider))).andReturn().getResponse();
        provider = JsonUtils.readValue(createResponse.getContentAsString(), MfaProvider.class);


        getMockMvc().perform(delete("/mfa-providers/" + provider.getId())
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(provider.getId()))
                .andReturn();

        assertEquals(1, eventListener.getEventCount());
    }

    @Test
    public void testNonExistentMfaProviderDelete() throws Exception {
        getMockMvc().perform(delete("/mfa-providers/invalid")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound())
                .andReturn();
        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    public void testDeleteForbiddenForNonAdmin() throws Exception {
        getMockMvc().perform(delete("/mfa-providers/invalid")
                .header("Authorization", "Bearer " + nonAdminToken))
                .andExpect(status().isForbidden())
                .andReturn();
        assertEquals(0, eventListener.getEventCount());
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