package org.cloudfoundry.identity.uaa.mock.zones;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.scim.event.GroupModifiedEvent;
import org.cloudfoundry.identity.uaa.scim.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.client.event.ClientCreateEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientDeleteEvent;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.KeyPair;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneModifiedEvent;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityZoneEndpointsMockMvcTests extends InjectedMockContextTest {
    public static final List<String> BASE_URLS = Arrays.asList("/identity-zones", "/identity-zones/");
    private String identityClientToken = null;
    private String identityClientZonesReadToken = null;
    private String identityClientZonesWriteToken = null;
    private String adminToken = null;
    private TestClient testClient = null;
    private MockMvcUtils mockMvcUtils = MockMvcUtils.utils();
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private TestApplicationEventListener<IdentityZoneModifiedEvent> zoneModifiedEventListener;
    private TestApplicationEventListener<ClientCreateEvent> clientCreateEventListener;
    private TestApplicationEventListener<ClientDeleteEvent> clientDeleteEventListener;
    private TestApplicationEventListener<GroupModifiedEvent> groupModifiedEventListener;
    private TestApplicationEventListener<UserModifiedEvent> userModifiedEventListener;
    private TestApplicationEventListener<AbstractUaaEvent> uaaEventListener;

    @Before
    public void setUp() throws Exception {
        testClient = new TestClient(getMockMvc());
        zoneModifiedEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), IdentityZoneModifiedEvent.class);
        clientCreateEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), ClientCreateEvent.class);
        clientDeleteEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), ClientDeleteEvent.class);
        groupModifiedEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), GroupModifiedEvent.class);
        userModifiedEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), UserModifiedEvent.class);
        uaaEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), AbstractUaaEvent.class);

        identityClientToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.read,zones.write,scim.zones");
        identityClientZonesReadToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.read");
        identityClientZonesWriteToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.write");
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "");
        IdentityZoneHolder.clear();
        zoneModifiedEventListener.clearEvents();
        clientCreateEventListener.clearEvents();
        clientDeleteEventListener.clearEvents();
        groupModifiedEventListener.clearEvents();
        userModifiedEventListener.clearEvents();
    }

    @After
    public void after() {
        IdentityZoneHolder.clear();
        mockMvcUtils.removeEventListener(getWebApplicationContext(), zoneModifiedEventListener);
        mockMvcUtils.removeEventListener(getWebApplicationContext(), clientCreateEventListener);
        mockMvcUtils.removeEventListener(getWebApplicationContext(), clientDeleteEventListener);
        mockMvcUtils.removeEventListener(getWebApplicationContext(), groupModifiedEventListener);
        mockMvcUtils.removeEventListener(getWebApplicationContext(), userModifiedEventListener);
    }

    private ScimUser createUser(String token, String subdomain) throws Exception {
        ScimUser user = getScimUser();

        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
            .header("Authorization", "Bearer " + token)
            .contentType(APPLICATION_JSON)
            .content(requestBody);
        if (subdomain != null && !subdomain.equals(""))
            post.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        MvcResult result = getMockMvc().perform(post)
            .andExpect(status().isCreated())
            .andExpect(header().string("ETag", "\"0\""))
            .andExpect(jsonPath("$.userName").value(user.getUserName()))
            .andExpect(jsonPath("$.emails[0].value").value(user.getUserName()))
            .andExpect(jsonPath("$.name.familyName").value(user.getFamilyName()))
            .andExpect(jsonPath("$.name.givenName").value(user.getGivenName()))
            .andReturn();

        return JsonUtils.readValue(result.getResponse().getContentAsString(), ScimUser.class);
    }

    private ScimUser getScimUser() {
        String email = "joe@" + generator.generate().toLowerCase() + ".com";
        ScimUser user = new ScimUser();
        user.setUserName(email);
        user.setName(new ScimUser.Name("Joe", "User"));
        user.addEmail(email);
        return user;
    }

    @Test
    public void readWithoutTokenShouldFail() throws Exception {
        for (String url : BASE_URLS) {
            getMockMvc().perform(get(url))
                .andExpect(status().isUnauthorized());
        }
    }

    @Test
    public void readWith_Write_TokenShouldFail() throws Exception {
        for (String url : BASE_URLS) {
            getMockMvc().perform(
                get(url)
                    .header("Authorization", "Bearer " + identityClientZonesWriteToken))
                .andExpect(status().isForbidden());
        }
    }

    @Test
    public void readWith_Read_TokenShouldSucceed() throws Exception {
        for (String url : BASE_URLS) {
            getMockMvc().perform(
                get(url)
                    .header("Authorization", "Bearer " + identityClientZonesReadToken))
                .andExpect(status().isOk());
        }
    }

    @Test
    public void testGetZoneAsIdentityClient() throws Exception {
        String id = generator.generate();
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken);
        IdentityZone retrieved = getIdentityZone(id, HttpStatus.OK, identityClientToken);
        assertEquals(created.getId(), retrieved.getId());
        assertEquals(created.getName(), retrieved.getName());
        assertEquals(created.getSubdomain(), retrieved.getSubdomain());
        assertEquals(created.getDescription(), retrieved.getDescription());
    }

    @Test
    public void testGetZonesAsIdentityClient() throws Exception {
        String id = generator.generate();
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken);

        getMockMvc().perform(
            get("/identity-zones/")
                .header("Authorization", "Bearer " + identityClientZonesWriteToken))
            .andExpect(status().isForbidden());

        MvcResult result = getMockMvc().perform(
            get("/identity-zones/")
                .header("Authorization", "Bearer " + identityClientToken))
            .andExpect(status().isOk())
            .andReturn();


        List<IdentityZone> zones = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<List<IdentityZone>>() {
        });
        IdentityZone retrieved = null;
        for (IdentityZone identityZone : zones) {
            if (identityZone.getId().equals(id)) {
                retrieved = identityZone;
            }
        }

        assertEquals(created.getId(), retrieved.getId());
        assertEquals(created.getName(), retrieved.getName());
        assertEquals(created.getSubdomain(), retrieved.getSubdomain());
        assertEquals(created.getDescription(), retrieved.getDescription());
    }

    @Test
    public void testGetZoneThatDoesntExist() throws Exception {
        String id = generator.generate();
        getIdentityZone(id, HttpStatus.NOT_FOUND, identityClientToken);
    }

    @Test
    public void testCreateZone() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken);
        assertEquals(id, zone.getId());
        assertEquals(id.toLowerCase(), zone.getSubdomain());
        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent, zoneModifiedEventListener, IdentityZone.getUaa().getId(), "http://localhost:8080/uaa/oauth/token", "identity");
    }

    @Test
    public void createZoneWithNoNameFailsWithUnprocessableEntity() throws Exception {
        String id = generator.generate();
        IdentityZone zone = this.getIdentityZone(id);
        zone.setName(null);

        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(zone)))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.error").value("invalid_identity_zone"))
            .andExpect(jsonPath("$.error_description").value("The identity zone must be given a name."));

        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void createZoneWithNoSubdomainFailsWithUnprocessableEntity() throws Exception {
        String id = generator.generate();
        IdentityZone zone = this.getIdentityZone(id);
        zone.setSubdomain(null);

        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(zone)))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.error").value("invalid_identity_zone"))
            .andExpect(jsonPath("$.error_description").value("The subdomain must be provided."));

        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testCreateZoneInsufficientScope() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        createZone(id, HttpStatus.FORBIDDEN, adminToken);

        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testCreateZoneNoToken() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        createZone(id, HttpStatus.UNAUTHORIZED, "");

        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }


    @Test
    public void testCreateZoneWithoutID() throws Exception {
        IdentityZone zone = createZone("", HttpStatus.CREATED, identityClientToken);
        assertTrue(StringUtils.hasText(zone.getId()));
        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);
    }


    @Test
    public void testUpdateNonExistentReturns403() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        IdentityZone identityZone = getIdentityZone(id);
        //zone doesn't exist and we don't have the token scope
        updateZone(identityZone, HttpStatus.FORBIDDEN, adminToken);

        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testUpdateUaaIsForbidden() throws Exception {
        updateZone(IdentityZone.getUaa(), HttpStatus.FORBIDDEN, identityClientToken);
        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testUpdateNonExistentReturns404() throws Exception {
        String id = generator.generate();
        IdentityZone identityZone = getIdentityZone(id);
        updateZone(identityZone, HttpStatus.NOT_FOUND, identityClientToken);

        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testUpdateWithSameDataReturns200() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken);

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        updateZone(created, HttpStatus.OK, identityClientToken);
        checkZoneAuditEventInUaa(2, AuditEventType.IdentityZoneModifiedEvent);
    }

    @Test
    public void testUpdateWithDifferentDataReturns200() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken);
        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);
        created.setDescription("updated description");
        IdentityZoneConfiguration definition = new IdentityZoneConfiguration(new TokenPolicy(3600, 7200));
        created.setConfig(definition);

        IdentityZone updated = updateZone(created, HttpStatus.OK, identityClientToken);
        assertEquals("updated description", updated.getDescription());
        assertEquals(JsonUtils.writeValueAsString(definition), JsonUtils.writeValueAsString(updated.getConfig()));
        checkZoneAuditEventInUaa(2, AuditEventType.IdentityZoneModifiedEvent);
    }

    @Test
    public void testUpdateZoneWithExistingSubdomain() throws Exception {
        String id1 = generator.generate();
        IdentityZone created1 = createZone(id1, HttpStatus.CREATED, identityClientToken);
        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        String id2 = generator.generate();
        IdentityZone created2 = createZone(id2, HttpStatus.CREATED, identityClientToken);
        checkZoneAuditEventInUaa(2, AuditEventType.IdentityZoneCreatedEvent);

        created1.setSubdomain(created2.getSubdomain());
        updateZone(created1, HttpStatus.CONFLICT, identityClientToken);
        checkZoneAuditEventInUaa(2, AuditEventType.IdentityZoneCreatedEvent);
    }

    @Test
    public void testUpdateZoneNoToken() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        IdentityZone identityZone = getIdentityZone(id);
        updateZone(identityZone, HttpStatus.UNAUTHORIZED, "");

        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testUpdateZoneInsufficientScope() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        IdentityZone identityZone = getIdentityZone(id);
        updateZone(identityZone, HttpStatus.FORBIDDEN, adminToken);

        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testCreateDuplicateZoneReturns409() throws Exception {
        String id = generator.generate();
        createZone(id, HttpStatus.CREATED, identityClientToken);

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        createZone(id, HttpStatus.CONFLICT, identityClientToken);

        assertEquals(1, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testCreateZoneAndIdentityProvider() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = getIdentityZone(id);
        TokenPolicy tokenPolicy = new TokenPolicy(3600, 7200);
        Map<String, KeyPair> keyPairs = new HashMap<>();
        KeyPair pair = new KeyPair();
        pair.setSigningKey("secret_key_1");
        pair.setVerificationKey("public_key_1");
        keyPairs.put("key_id_1", pair);
        KeyPair pair2 = new KeyPair();
        pair.setSigningKey("secret_key_2");
        pair.setVerificationKey("public_key_2");
        keyPairs.put("key_id_2", pair2);
        tokenPolicy.setKeys(keyPairs);
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setCertificate("saml-certificate");
        samlConfig.setPrivateKey("saml-private-key");
        IdentityZoneConfiguration definition = new IdentityZoneConfiguration(tokenPolicy);
        identityZone.setConfig(definition.setSamlConfig(samlConfig));

        for (String url : BASE_URLS) {
            getMockMvc().perform(
                post(url)
                    .header("Authorization", "Bearer " + identityClientZonesReadToken)
                    .contentType(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isForbidden());
        }

        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
            .andExpect(status().isCreated());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        IdentityProviderProvisioning idpp = (IdentityProviderProvisioning) getWebApplicationContext().getBean("identityProviderProvisioning");
        IdentityProvider idp1 = idpp.retrieveByOrigin(UAA, identityZone.getId());
        IdentityProvider idp2 = idpp.retrieveByOrigin(UAA, IdentityZone.getUaa().getId());
        assertNotEquals(idp1, idp2);

        IdentityZoneProvisioning identityZoneProvisioning = (IdentityZoneProvisioning) getWebApplicationContext().getBean("identityZoneProvisioning");
        IdentityZone createdZone = identityZoneProvisioning.retrieve(id);

        assertEquals(JsonUtils.writeValueAsString(definition), JsonUtils.writeValueAsString(createdZone.getConfig()));
        assertEquals("saml-certificate", createdZone.getConfig().getSamlConfig().getCertificate());
        assertEquals("saml-private-key", createdZone.getConfig().getSamlConfig().getPrivateKey());
    }

    @Test
    public void test_delete_zone_cleans_db() throws Exception {
        IdentityProviderProvisioning idpp = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        ScimGroupProvisioning groupProvisioning = getWebApplicationContext().getBean(ScimGroupProvisioning.class);
        ScimUserProvisioning userProvisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        ScimGroupMembershipManager membershipManager = getWebApplicationContext().getBean(ScimGroupMembershipManager.class);
        ScimGroupExternalMembershipManager externalMembershipManager = getWebApplicationContext().getBean(ScimGroupExternalMembershipManager.class);
        ApprovalStore approvalStore = getWebApplicationContext().getBean(ApprovalStore.class);
        JdbcTemplate template = getWebApplicationContext().getBean(JdbcTemplate.class);

        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken);

        //create zone and clients
        BaseClientDetails client = new BaseClientDetails("limited-client", null, "openid", "authorization_code",
                                                         "uaa.resource");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(UAA));
        client.addAdditionalInformation("foo", "bar");
        for (String url : Arrays.asList("","/")) {
            getMockMvc().perform(
                post("/identity-zones/" + zone.getId() + "/clients"+url)
                    .header("Authorization", "Bearer " + identityClientZonesReadToken)
                    .contentType(APPLICATION_JSON)
                    .accept(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isForbidden());
        }

        MvcResult result = getMockMvc().perform(
            post("/identity-zones/" + zone.getId() + "/clients")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client)))
            .andExpect(status().isCreated()).andReturn();
        BaseClientDetails created = JsonUtils.readValue(result.getResponse().getContentAsString(), BaseClientDetails.class);
        assertNull(created.getClientSecret());
        assertEquals("zones.write", created.getAdditionalInformation().get(ClientConstants.CREATED_WITH));
        assertEquals(Collections.singletonList(UAA), created.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS));
        assertEquals("bar", created.getAdditionalInformation().get("foo"));

        //ensure that UAA provider is there
        assertNotNull(idpp.retrieveByOrigin(UAA, zone.getId()));
        assertEquals(UAA, idpp.retrieveByOrigin(UAA, zone.getId()).getOriginKey());

        //create login-server provider
        IdentityProvider provider = new IdentityProvider()
            .setOriginKey(LOGIN_SERVER)
            .setActive(true)
            .setIdentityZoneId(zone.getId())
            .setName("Delete Test")
            .setType(LOGIN_SERVER);
        IdentityZoneHolder.set(zone);
        provider = idpp.create(provider);
        assertNotNull(idpp.retrieveByOrigin(LOGIN_SERVER, zone.getId()));
        assertEquals(provider.getId(), idpp.retrieveByOrigin(LOGIN_SERVER, zone.getId()).getId());

        //create user and add user to group
        ScimUser user = getScimUser();
        user.setOrigin(LOGIN_SERVER);
        user = userProvisioning.createUser(user, "");
        assertNotNull(userProvisioning.retrieve(user.getId()));
        assertEquals(zone.getId(), user.getZoneId());

        //create group
        ScimGroup group = new ScimGroup("Delete Test Group");
        group.setZoneId(zone.getId());
        group = groupProvisioning.create(group);
        membershipManager.addMember(group.getId(), new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER, Arrays.asList(ScimGroupMember.Role.MEMBER)));
        assertEquals(zone.getId(), group.getZoneId());
        assertNotNull(groupProvisioning.retrieve(group.getId()));
        assertEquals("Delete Test Group", groupProvisioning.retrieve(group.getId()).getDisplayName());
        assertEquals(1, membershipManager.getMembers(group.getId(), null, false).size());

        //failed authenticated user
        getMockMvc().perform(
            post("/login.do")
                .header("Host", zone.getSubdomain()+".localhost")
                .with(cookieCsrf())
                .accept(TEXT_HTML_VALUE)
                .param("username", user.getUserName())
                .param("password", "adasda")
        )
            .andExpect(status().isFound());

        //ensure we have some audit records
        //this doesn't work yet
        //assertThat(template.queryForObject("select count(*) from sec_audit where identity_zone_id=?", new Object[] {user.getZoneId()}, Integer.class), greaterThan(0));
        //create an external group map
        IdentityZoneHolder.set(zone);
        ScimGroupExternalMember externalMember = externalMembershipManager.mapExternalGroup(group.getId(), "externalDeleteGroup", LOGIN_SERVER);
        assertEquals(1, externalMembershipManager.getExternalGroupMapsByGroupId(group.getId(), LOGIN_SERVER).size());

        //add user approvals
        approvalStore.addApproval(
            new Approval()
                .setClientId(client.getClientId())
                .setScope("openid")
                .setStatus(Approval.ApprovalStatus.APPROVED)
                .setUserId(user.getId())
        );
        assertEquals(1, approvalStore.getApprovals(user.getId(), client.getClientId()).size());

        //perform zone delete
        getMockMvc().perform(
            delete("/identity-zones/{id}", zone.getId())
                .header("Authorization", "Bearer " + identityClientToken)
                .accept(APPLICATION_JSON))
            .andExpect(status().isOk());

        getMockMvc().perform(
            delete("/identity-zones/{id}", zone.getId())
                .header("Authorization", "Bearer " + identityClientToken)
                .accept(APPLICATION_JSON))
            .andExpect(status().isNotFound());

        assertThat(template.queryForObject("select count(*) from identity_zone where id=?", new Object[] {zone.getId()}, Integer.class), is(0));

        assertThat(template.queryForObject("select count(*) from oauth_client_details where identity_zone_id=?", new Object[] {zone.getId()}, Integer.class), is(0));

        assertThat(template.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[] {zone.getId()}, Integer.class), is(0));

        assertThat(template.queryForObject("select count(*) from sec_audit where identity_zone_id=?", new Object[] {zone.getId()}, Integer.class), is(0));

        assertThat(template.queryForObject("select count(*) from users where identity_zone_id=?", new Object[] {zone.getId()}, Integer.class), is(0));

        assertThat(template.queryForObject("select count(*) from external_group_mapping where origin=?", new Object[] {LOGIN_SERVER}, Integer.class), is(0));
        try {
            externalMembershipManager.getExternalGroupMapsByGroupId(group.getId(), LOGIN_SERVER);
            fail("no external groups should be found");
        } catch (ScimResourceNotFoundException e) {
        }

        assertThat(template.queryForObject("select count(*) from authz_approvals where user_id=?", new Object[] {user.getId()}, Integer.class), is(0));
        assertEquals(0, approvalStore.getApprovals(user.getId(), client.getClientId()).size());



    }

    @Test
    public void testDeleteZonePublishesEvent() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken);

        uaaEventListener.clearEvents();

        getMockMvc().perform(
            delete("/identity-zones/{id}", zone.getId())
                .header("Authorization", "Bearer " + identityClientToken)
                .accept(APPLICATION_JSON))
            .andExpect(status().isOk());

        assertThat(uaaEventListener.getEventCount(), is(1));
        AbstractUaaEvent event = uaaEventListener.getLatestEvent();
        assertThat(event, instanceOf(EntityDeletedEvent.class));
        assertThat(((EntityDeletedEvent) event).getDeleted(), instanceOf(IdentityZone.class));

        IdentityZone deletedZone = (IdentityZone) ((EntityDeletedEvent) event).getDeleted();
        assertThat(deletedZone.getId(), is(id));
        assertThat(event.getIdentityZone().getId(), is(id));
    }

    @Test
    public void testCreateAndDeleteLimitedClientInNewZoneUsingZoneEndpoint() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken);
        BaseClientDetails client = new BaseClientDetails("limited-client", null, "openid", "authorization_code",
                                                         "uaa.resource");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(UAA));
        client.addAdditionalInformation("foo", "bar");
        for (String url : Arrays.asList("","/")) {
            getMockMvc().perform(
                post("/identity-zones/" + zone.getId() + "/clients"+url)
                    .header("Authorization", "Bearer " + identityClientZonesReadToken)
                    .contentType(APPLICATION_JSON)
                    .accept(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isForbidden());
        }

        MvcResult result = getMockMvc().perform(
            post("/identity-zones/" + zone.getId() + "/clients")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client)))
            .andExpect(status().isCreated()).andReturn();
        BaseClientDetails created = JsonUtils.readValue(result.getResponse().getContentAsString(), BaseClientDetails.class);
        assertNull(created.getClientSecret());
        assertEquals("zones.write", created.getAdditionalInformation().get(ClientConstants.CREATED_WITH));
        assertEquals(Collections.singletonList(UAA), created.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS));
        assertEquals("bar", created.getAdditionalInformation().get("foo"));
        checkAuditEventListener(1, AuditEventType.ClientCreateSuccess, clientCreateEventListener, id, "http://localhost:8080/uaa/oauth/token", "identity");

        for (String url : Arrays.asList("","/")) {
            getMockMvc().perform(
                delete("/identity-zones/" + zone.getId() + "/clients/" + created.getClientId(), IdentityZone.getUaa().getId()+url)
                    .header("Authorization", "Bearer " + identityClientZonesReadToken)
                    .accept(APPLICATION_JSON))
                .andExpect(status().isForbidden());
        }
        getMockMvc().perform(
            delete("/identity-zones/" + zone.getId() + "/clients/" + created.getClientId(), IdentityZone.getUaa().getId())
                .header("Authorization", "Bearer " + identityClientToken)
                .accept(APPLICATION_JSON))
            .andExpect(status().isOk());

        checkAuditEventListener(1, AuditEventType.ClientDeleteSuccess, clientDeleteEventListener, id, "http://localhost:8080/uaa/oauth/token", "identity");
    }

    @Test
    public void testCreateAndDeleteLimitedClientInUAAZoneReturns403() throws Exception {
        BaseClientDetails client = new BaseClientDetails("limited-client", null, "openid", "authorization_code",
                                                         "uaa.resource");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(UAA));
        getMockMvc().perform(
            post("/identity-zones/uaa/clients")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client)))
            .andExpect(status().isForbidden());
        assertEquals(0, clientCreateEventListener.getEventCount());

        getMockMvc().perform(
            delete("/identity-zones/uaa/clients/admin")
                .header("Authorization", "Bearer " + identityClientToken)
                .accept(APPLICATION_JSON))
            .andExpect(status().isForbidden());

        assertEquals(0, clientDeleteEventListener.getEventCount());
    }

    @Test
    public void testCreateAdminClientInNewZoneUsingZoneEndpointReturns400() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken);
        BaseClientDetails client = new BaseClientDetails("admin-client", null, null, "client_credentials",
                                                         "clients.write");
        client.setClientSecret("secret");
        getMockMvc().perform(
            post("/identity-zones/" + zone.getId() + "/clients")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(client)))
            .andExpect(status().isBadRequest());
    }

    @Test
    public void testCreatesZonesWithDuplicateSubdomains() throws Exception {
        String subdomain = UUID.randomUUID().toString();
        String id1 = UUID.randomUUID().toString();
        String id2 = UUID.randomUUID().toString();
        IdentityZone identityZone1 = MultitenancyFixture.identityZone(id1, subdomain);
        IdentityZone identityZone2 = MultitenancyFixture.identityZone(id2, subdomain);
        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone1)))
            .andExpect(status().isCreated());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone2)))
            .andExpect(status().isConflict());

        assertEquals(1, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testZoneAdminTokenAgainstZoneEndpoints() throws Exception {
        String zone1 = generator.generate().toLowerCase();
        String zone2 = generator.generate().toLowerCase();

        IdentityZoneCreationResult result1 = MockMvcUtils.utils().createOtherIdentityZoneAndReturnResult(zone1, getMockMvc(), getWebApplicationContext(), null);
        IdentityZoneCreationResult result2 = MockMvcUtils.utils().createOtherIdentityZoneAndReturnResult(zone2, getMockMvc(), getWebApplicationContext(), null);

        MvcResult result = getMockMvc().perform(
            get("/identity-zones")
                .header("Authorization", "Bearer " + result1.getZoneAdminToken())
                .header(IdentityZoneSwitchingFilter.HEADER, result1.getIdentityZone().getSubdomain())
                .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();

        //test read your own zone only
        List<IdentityZone> zones = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<List<IdentityZone>>() {
        });
        assertEquals(1, zones.size());
        assertEquals(zone1, zones.get(0).getSubdomain());

        //test write your own
        getMockMvc().perform(
            put("/identity-zones/" + result1.getIdentityZone().getId())
                .header("Authorization", "Bearer " + result1.getZoneAdminToken())
                .header(IdentityZoneSwitchingFilter.HEADER, result1.getIdentityZone().getSubdomain())
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(result1.getIdentityZone())))
            .andExpect(status().isOk());

        //test write someone elses
        getMockMvc().perform(
            put("/identity-zones/" + result2.getIdentityZone().getId())
                .header("Authorization", "Bearer " + result1.getZoneAdminToken())
                .header(IdentityZoneSwitchingFilter.HEADER, result1.getIdentityZone().getSubdomain())
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(result2.getIdentityZone())))
            .andExpect(status().isForbidden());

        //test create as zone admin
        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + result1.getZoneAdminToken())
                .header(IdentityZoneSwitchingFilter.HEADER, result1.getIdentityZone().getSubdomain())
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(result2.getIdentityZone())))
            .andExpect(status().isForbidden());

    }

    @Test
    public void testSuccessfulUserManagementInZoneUsingAdminClient() throws Exception {
        String subdomain = generator.generate().toLowerCase();
        BaseClientDetails adminClient = new BaseClientDetails("admin", null, null, "client_credentials", "scim.read,scim.write");
        adminClient.setClientSecret("admin-secret");
        IdentityZoneCreationResult creationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), adminClient);
        IdentityZone identityZone = creationResult.getIdentityZone();

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);
        checkAuditEventListener(1, AuditEventType.GroupCreatedEvent, groupModifiedEventListener, IdentityZone.getUaa().getId(), "http://localhost:8080/uaa/oauth/token", "identity");
        checkAuditEventListener(1, AuditEventType.ClientCreateSuccess, clientCreateEventListener, identityZone.getId(), "http://localhost:8080/uaa/oauth/token", creationResult.getZoneAdminUser().getId());

        String scimAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write,scim.read", subdomain);
        ScimUser user = createUser(scimAdminToken, subdomain);
        checkAuditEventListener(1, AuditEventType.UserCreatedEvent, userModifiedEventListener, identityZone.getId(), "http://" + subdomain + ".localhost:8080/uaa/oauth/token", "admin");

        user.setUserName("updated-username@test.com");
        MockHttpServletRequestBuilder put = put("/Users/" + user.getId())
            .header("Authorization", "Bearer " + scimAdminToken)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(user))
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        MvcResult result = getMockMvc().perform(put)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.userName").value(user.getUserName()))
            .andReturn();

        checkAuditEventListener(2, AuditEventType.UserModifiedEvent, userModifiedEventListener, identityZone.getId(), "http://" + subdomain + ".localhost:8080/uaa/oauth/token", "admin");
        user = JsonUtils.readValue(result.getResponse().getContentAsString(), ScimUser.class);
        List<ScimUser> users = getUsersInZone(subdomain, scimAdminToken);
        assertTrue(users.contains(user));
        assertEquals(1, users.size());

        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId())
            .header("Authorization", "Bearer " + scimAdminToken)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        getMockMvc().perform(delete)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(user.getId()))
            .andReturn();

        checkAuditEventListener(3, AuditEventType.UserDeletedEvent, userModifiedEventListener, identityZone.getId(), "http://" + subdomain + ".localhost:8080/uaa/oauth/token", "admin");
        users = getUsersInZone(subdomain, scimAdminToken);
        assertEquals(0, users.size());
    }

    @Test
    public void testCreateAndListUsersInOtherZoneIsUnauthorized() throws Exception {
        String subdomain = generator.generate();
        mockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        String defaultZoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write,scim.read");

        ScimUser user = getScimUser();

        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
            .header("Authorization", "Bearer " + defaultZoneAdminToken)
            .contentType(APPLICATION_JSON)
            .content(requestBody);

        getMockMvc().perform(post).andExpect(status().isUnauthorized());

        MockHttpServletRequestBuilder get = get("/Users").header("Authorization", "Bearer " + defaultZoneAdminToken);
        if (subdomain != null && !subdomain.equals(""))
            get.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        getMockMvc().perform(get).andExpect(status().isUnauthorized()).andReturn();
    }

    @Test
    public void testModifyandDeleteUserInOtherZoneIsUnauthorized() throws Exception {
        String scimWriteToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        ScimUser user = createUser(scimWriteToken, null);

        String subdomain = generator.generate();
        mockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        String scimAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write,scim.read", subdomain);
        user.setUserName("updated-user@defaultzone.com");

        MockHttpServletRequestBuilder put = put("/Users/" + user.getId())
            .header("Authorization", "Bearer " + scimAdminToken)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(user));

        getMockMvc().perform(put)
            .andExpect(status().isUnauthorized())
            .andReturn();

        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId())
            .header("Authorization", "Bearer " + scimAdminToken)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON);

        getMockMvc().perform(delete)
            .andExpect(status().isUnauthorized())
            .andReturn();
    }

    @Test
    public void userCanReadAZone_withZoneZoneIdReadToken() throws Exception {
        String scimWriteToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        ScimUser user = createUser(scimWriteToken, null);

        String id = generator.generate().toLowerCase();
        IdentityZone identityZone = createZone(id, HttpStatus.CREATED, identityClientToken);

        ScimGroup group = new ScimGroup();
        String zoneReadScope = "zones." + identityZone.getId() + ".read";
        group.setDisplayName(zoneReadScope);
        group.setMembers(Collections.singletonList(new ScimGroupMember(user.getId())));
        getMockMvc().perform(
            post("/Groups/zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(group)))
            .andExpect(status().isCreated());

        String userAccessToken = mockMvcUtils.getUserOAuthAccessTokenAuthCode(getMockMvc(), "identity", "identitysecret", user.getId(), user.getUserName(), user.getPassword(), "zones." + identityZone.getId() + ".read");

        MvcResult result = getMockMvc().perform(
            get("/identity-zones/" + identityZone.getId())
                .header("Authorization", "Bearer " + userAccessToken)
                .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getSubdomain())
                .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();

        IdentityZone zoneResult = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<IdentityZone>() {
        });
        assertEquals(identityZone, zoneResult);
    }

    private IdentityZone getIdentityZone(String id, HttpStatus expect, String token) throws Exception {
        MvcResult result = getMockMvc().perform(
            get("/identity-zones/" + id)
                .header("Authorization", "Bearer " + token))
            .andExpect(status().is(expect.value()))
            .andReturn();

        if (expect.is2xxSuccessful()) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityZone.class);
        }
        return null;
    }

    private IdentityZone createZone(String id, HttpStatus expect, String token) throws Exception {
        IdentityZone identityZone = getIdentityZone(id);
        MvcResult result = getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
            .andExpect(status().is(expect.value()))
            .andReturn();

        if (expect.is2xxSuccessful()) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityZone.class);
        }
        return null;
    }

    private IdentityZone updateZone(IdentityZone identityZone, HttpStatus expect, String token) throws Exception {
        MvcResult result = getMockMvc().perform(
            put("/identity-zones/" + identityZone.getId())
                .header("Authorization", "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
            .andExpect(status().is(expect.value()))
            .andReturn();

        if (expect.is2xxSuccessful()) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityZone.class);
        }
        return null;
    }

    private <T extends AbstractUaaEvent> void checkZoneAuditEventInUaa(int eventCount, AuditEventType eventType) {
        checkAuditEventListener(eventCount, eventType, zoneModifiedEventListener, IdentityZone.getUaa().getId(), "http://localhost:8080/uaa/oauth/token", "identity");
    }

    private <T extends AbstractUaaEvent> void checkAuditEventListener(int eventCount, AuditEventType eventType, TestApplicationEventListener<T> eventListener, String identityZoneId, String issuer, String subject) {
        T event = eventListener.getLatestEvent();
        assertEquals(eventCount, eventListener.getEventCount());
        if (eventCount > 0) {
            assertEquals(eventType, event.getAuditEvent().getType());
            assertEquals(identityZoneId, event.getAuditEvent().getIdentityZoneId());
            String origin = event.getAuditEvent().getOrigin();
            assertTrue(origin.contains("iss=" + issuer));
            assertTrue(origin.contains("sub=" + subject));
        }
    }

    private IdentityZone getIdentityZone(String id) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(StringUtils.hasText(id) ? id : new RandomValueStringGenerator().generate());
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    private List<ScimUser> getUsersInZone(String subdomain, String token) throws Exception {
        MockHttpServletRequestBuilder get = get("/Users").header("Authorization", "Bearer " + token);
        if (subdomain != null && !subdomain.equals(""))
            get.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        MvcResult mvcResult = getMockMvc().perform(get).andExpect(status().isOk()).andReturn();

        JsonNode root = JsonUtils.readTree(mvcResult.getResponse().getContentAsString());
        return JsonUtils.readValue(root.get("resources").toString(), new TypeReference<List<ScimUser>>() {
        });
    }
}
