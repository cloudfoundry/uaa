package org.cloudfoundry.identity.uaa.mock.mfa_provider;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.mfa.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa.JdbcMfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa.MfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.context.support.GenericWebApplicationContext;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.constructGoogleMfaProvider;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
public class MfaProviderEndpointsMockMvcTests {
    @Autowired
    public GenericWebApplicationContext webApplicationContext;
    private String adminToken;
    private String nonAdminToken;
    private TestApplicationEventListener<EntityDeletedEvent> eventListener;

    private MfaProviderProvisioning mfaProviderProvisioning;

    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    void setup() throws Exception {
        TestClient testClient = new TestClient(mockMvc);

        mfaProviderProvisioning = webApplicationContext.getBean(JdbcMfaProviderProvisioning.class);
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret clients.admin uaa.admin");
        nonAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write clients.admin");
        eventListener = MockMvcUtils.addEventListener(webApplicationContext, EntityDeletedEvent.class);
    }

    @Test
    void testCreateGoogleMfaProviderConfigDefaults() throws Exception {
        MfaProvider mfaProvider = constructGoogleMfaProvider();
        mfaProvider.setConfig(null);
        MvcResult mfaResponse = mockMvc.perform(
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
    void testCreateGoogleMfaProviderInvalidType() throws Exception {
        MfaProvider mfaProvider = constructGoogleMfaProvider();
        ObjectNode mfaAsJSON = (ObjectNode) JsonUtils.readTree(JsonUtils.writeValueAsString(mfaProvider));
        mfaAsJSON.put("type", "not-google-authenticator");
        ResultActions authorization = mockMvc.perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaAsJSON)));
        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY.value(), authorization.andReturn().getResponse().getStatus());
    }

    @Test
    void testCreateMfaProvider() throws Exception {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleMfaProvider();
        String name = new RandomValueStringGenerator(5).generate();
        mfaProvider.setName(name);
        MvcResult mfaResponse = mockMvc.perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();

        mfaProvider = JsonUtils.readValue(mfaResponse.getResponse().getContentAsString(), MfaProvider.class);

        assertEquals(HttpStatus.CREATED.value(), mfaResponse.getResponse().getStatus());
        assertEquals(name, mfaProvider.getName());
        assertNotNull(mfaProvider.getId());
    }

    @Test
    void testCreateMfaProviderInvalidIssuer() throws Exception {
        GoogleMfaProviderConfig config = new GoogleMfaProviderConfig();
        config.setIssuer("invalid:issuer");
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleMfaProvider().setConfig(config);
        String name = new RandomValueStringGenerator(5).generate();
        mfaProvider.setName(name);
        MvcResult mfaResponse = mockMvc.perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();

        assertEquals(HttpStatus.UNPROCESSABLE_ENTITY.value(), mfaResponse.getResponse().getStatus());
    }

    @Test
    void testCreateDuplicate() throws Exception {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleProvider();
        mfaProvider.setConfig(null);
        mockMvc.perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();

        mockMvc.perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider)))
                .andDo(print())
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("invalid_mfa_provider"))
                .andExpect(jsonPath("$.error_description").value("An MFA Provider with that name already exists."));
    }

    @Test
    void testCreateMfaForOtherZone() throws Exception {
        IdentityZone identityZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, adminToken);

        MfaProvider mfaProvider = constructGoogleMfaProvider();
        MvcResult mfaResponse = mockMvc.perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();
        assertEquals(HttpStatus.CREATED.value(), mfaResponse.getResponse().getStatus());
    }

    @Test
    void testUpdateIsNotAllowed() throws Exception {
        mockMvc.perform(put("/mfa-providers/invalid")
                .header("Authorization", "bearer " + adminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(new MfaProvider<>())))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    void testUpdateForbiddenNonAdmin() throws Exception {
        mockMvc.perform(put("/mfa-providers/invalid")
                .header("Authorization", "bearer " + nonAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(new MfaProvider<>())))
                .andExpect(status().isForbidden());
    }

    @Test
    void testRetrieveMfaProviders() throws Exception {
        int mfaProvidersCount = mfaProviderProvisioning.retrieveAll(IdentityZoneHolder.get().getId()).size();
        MvcResult authorization = mockMvc.perform(
                get("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)).andReturn();

        assertEquals(HttpStatus.OK.value(), authorization.getResponse().getStatus());
        List<MfaProvider> mfaProviders = JsonUtils.readValue(authorization.getResponse().getContentAsString(), List.class);
        assertEquals(mfaProvidersCount, mfaProviders.size());
    }

    @Test
    void testRetrieveMfaProviderById() throws Exception {
        MfaProvider<GoogleMfaProviderConfig> createdProvider = constructGoogleMfaProvider();
        createdProvider.setIdentityZoneId(IdentityZoneHolder.get().getId());
        createdProvider = mfaProviderProvisioning.create(createdProvider, IdentityZoneHolder.get().getId());
        MvcResult result = mockMvc.perform(
                get("/mfa-providers/" + createdProvider.getId())
                        .header("Authorization", "Bearer " + adminToken)).andReturn();

        assertEquals(HttpStatus.OK.value(), result.getResponse().getStatus());
        assertEquals(JsonUtils.writeValueAsString(createdProvider), result.getResponse().getContentAsString());
    }

    @Test
    void testGetMfaInOtherZone() throws Exception {
        IdentityZone identityZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, adminToken);

        MfaProvider mfaProvider = constructGoogleMfaProvider();
        MvcResult createResult = mockMvc.perform(
                post("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn();
        mfaProvider = JsonUtils.readValue(createResult.getResponse().getContentAsString(), MfaProvider.class);


        MvcResult mfaListResult = mockMvc.perform(
                get("/mfa-providers")
                        .header("Authorization", "Bearer " + adminToken)
                        .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())).andReturn();
        List<Map> mfaProviders = JsonUtils.readValue(mfaListResult.getResponse().getContentAsString(), List.class);
        List providerIds = mfaProviders.stream().map(provider -> provider.get("id")).collect(Collectors.toList());
        assertTrue(providerIds.contains(mfaProvider.getId()));
    }

    @Test
    void testRetrieveMfaProviderByIdInvalid() throws Exception {
        MvcResult authorization = mockMvc.perform(
                get("/mfa-providers/abcd")
                        .header("Authorization", "Bearer " + adminToken)).andReturn();

        assertEquals(HttpStatus.NOT_FOUND.value(), authorization.getResponse().getStatus());
    }

    @Test
    void testDeleteMfaProvider() throws Exception {
        MfaProvider provider = constructGoogleMfaProvider();
        MockHttpServletResponse createResponse = mockMvc.perform(post("/mfa-providers")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(provider))).andReturn().getResponse();
        provider = JsonUtils.readValue(createResponse.getContentAsString(), MfaProvider.class);


        mockMvc.perform(delete("/mfa-providers/" + provider.getId())
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(provider.getId()))
                .andReturn();

        assertEquals(1, eventListener.getEventCount());
    }

    @Test
    void testDeleteZoneActiveMfaProviderShouldFail() throws Exception {
        IdentityZone identityZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, adminToken);

        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleMfaProvider();
        mfaProvider = JsonUtils.readValue(mockMvc.perform(post("/mfa-providers")
                .header("Authorization", "Bearer " + adminToken)
                .header("X-Identity-Zone-Id", identityZone.getId())
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn().getResponse().getContentAsString(), MfaProvider.class);

        identityZone.getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        MockMvcUtils.updateIdentityZone(identityZone, webApplicationContext);

        String deleteResponse = mockMvc.perform(delete("/mfa-providers/" + mfaProvider.getId())
                .header("Authorization", "Bearer " + adminToken)
                .header("X-Identity-Zone-Id", identityZone.getId()))
                .andExpect(status().isConflict()).andReturn().getResponse().getContentAsString();

        assertThat(deleteResponse, containsString("MFA provider is currently active on zone: " + identityZone.getId()));

    }

    @Test
    void testNonExistentMfaProviderDelete() throws Exception {
        mockMvc.perform(delete("/mfa-providers/invalid")
                .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound())
                .andReturn();
        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    void testDeleteForbiddenForNonAdmin() throws Exception {
        mockMvc.perform(delete("/mfa-providers/invalid")
                .header("Authorization", "Bearer " + nonAdminToken))
                .andExpect(status().isForbidden())
                .andReturn();
        assertEquals(0, eventListener.getEventCount());
    }

    @Test
    void testDeleteZoneAlsoDeletesMfaProviderInThatZone() throws Exception {
        IdentityZone identityZone = MockMvcUtils.createZoneUsingWebRequest(mockMvc, adminToken);

        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleMfaProvider();
        MockHttpServletResponse response = mockMvc.perform(post("/mfa-providers")
                .header("Authorization", "Bearer " + adminToken)
                .header("X-Identity-Zone-Id", identityZone.getId())
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(mfaProvider))).andReturn().getResponse();
        mfaProvider = JsonUtils.readValue(response.getContentAsString(), MfaProvider.class);
        MfaProviderProvisioning providerProvisioning = webApplicationContext.getBean(JdbcMfaProviderProvisioning.class);
        providerProvisioning.retrieve(mfaProvider.getId(), identityZone.getId());

        MockMvcUtils.deleteIdentityZone(identityZone.getId(), mockMvc);

        final String mfaProviderId = mfaProvider.getId();
        assertThrows(EmptyResultDataAccessException.class, () -> providerProvisioning.retrieve(mfaProviderId, identityZone.getId()));
    }

    private MfaProvider<GoogleMfaProviderConfig> constructGoogleProvider() {
        return new MfaProvider<GoogleMfaProviderConfig>()
                .setName(new RandomValueStringGenerator(10).generate())
                .setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR)
                .setIdentityZoneId(IdentityZoneHolder.get().getId())
                .setConfig(constructGoogleProviderConfiguration());
    }

    private GoogleMfaProviderConfig constructGoogleProviderConfiguration() {
        return new GoogleMfaProviderConfig();
    }
}