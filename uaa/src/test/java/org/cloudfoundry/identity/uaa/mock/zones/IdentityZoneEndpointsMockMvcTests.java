package org.cloudfoundry.identity.uaa.mock.zones;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.GroupModifiedEvent;
import org.cloudfoundry.identity.uaa.audit.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.client.ClientConstants;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.oauth.event.ClientCreateEvent;
import org.cloudfoundry.identity.uaa.oauth.event.ClientDeleteEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneModifiedEvent;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityZoneEndpointsMockMvcTests extends InjectedMockContextTest {
    private String identityClientToken = null;
    private String adminToken = null;
    private TestClient testClient = null;
    private MockMvcUtils mockMvcUtils = MockMvcUtils.utils();
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private TestApplicationEventListener<IdentityZoneModifiedEvent> zoneModifiedEventListener;
    private TestApplicationEventListener<ClientCreateEvent> clientCreateEventListener;
    private TestApplicationEventListener<ClientDeleteEvent> clientDeleteEventListener;
    private TestApplicationEventListener<GroupModifiedEvent> groupModifiedEventListener;
    private TestApplicationEventListener<UserModifiedEvent> userModifiedEventListener;

    @Before
    public void setUp() throws Exception {
        testClient = new TestClient(getMockMvc());
        zoneModifiedEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), IdentityZoneModifiedEvent.class);
        clientCreateEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), ClientCreateEvent.class);
        clientDeleteEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), ClientDeleteEvent.class);
        groupModifiedEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), GroupModifiedEvent.class);
        userModifiedEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), UserModifiedEvent.class);


        identityClientToken = testClient.getClientCredentialsOAuthAccessToken(
            "identity",
            "identitysecret",
            "zones.read,zones.write");
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
    }

    private ScimUser createUser(String token, String subdomain) throws Exception {
        ScimUser user = getScimUser();

        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
                .header("Authorization", "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content(requestBody);
        if (subdomain != null && !subdomain.equals("")) post.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

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
        String email = "joe@"+generator.generate().toLowerCase()+".com";
        ScimUser user = new ScimUser();
        user.setUserName(email);
        user.setName(new ScimUser.Name("Joe", "User"));
        user.addEmail(email);
        return user;
    }

    @Test
    public void testGetZoneAsIdentityClient() throws Exception  {
        String id = generator.generate();
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken);
        IdentityZone retrieved = getIdentityZone(id, HttpStatus.OK, identityClientToken);
        assertEquals(created.getId(), retrieved.getId());
        assertEquals(created.getName(), retrieved.getName());
        assertEquals(created.getSubdomain(), retrieved.getSubdomain());
        assertEquals(created.getDescription(), retrieved.getDescription());
    }

    @Test
    public void testGetZonesAsIdentityClient() throws Exception  {
        String id = generator.generate();
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken);
        MvcResult result = getMockMvc().perform(get("/identity-zones/")
            .header("Authorization", "Bearer " + identityClientToken))
                .andExpect(status().isOk())
                .andReturn();


        List<IdentityZone> zones = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<List<IdentityZone>>() {});
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
    public void testGetZoneThatDoesntExist() throws Exception  {
        String id = generator.generate();
        getIdentityZone(id, HttpStatus.NOT_FOUND, identityClientToken);
    }

    @Test
    public void testCreateZone() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken);
        assertEquals(id, zone.getId());
        assertEquals(id, zone.getSubdomain());
        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent, zoneModifiedEventListener, IdentityZone.getUaa().getId(), "http://localhost:8080/uaa/oauth/token", "identity");
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
        IdentityZone updated = updateZone(created, HttpStatus.OK, identityClientToken);
        assertEquals("updated description", updated.getDescription());
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

        getMockMvc().perform(post("/identity-zones")
            .header("Authorization", "Bearer " + identityClientToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(identityZone)))
            .andExpect(status().isCreated())
            .andReturn();

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        IdentityProviderProvisioning idpp = (IdentityProviderProvisioning) getWebApplicationContext().getBean("identityProviderProvisioning");
        IdentityProvider idp1 = idpp.retrieveByOrigin(Origin.UAA, identityZone.getId());
        IdentityProvider idp2 = idpp.retrieveByOrigin(Origin.UAA, IdentityZone.getUaa().getId());
        assertNotEquals(idp1,  idp2);
    }

    @Test
    public void testCreateAndDeleteLimitedClientInNewZoneUsingZoneEndpoint() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken);
        BaseClientDetails client = new BaseClientDetails("limited-client", null, "openid", "authorization_code",
                "uaa.resource");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(Origin.UAA));
        client.addAdditionalInformation("foo", "bar");
        MvcResult result = getMockMvc().perform(post("/identity-zones/" + zone.getId() + "/clients")
            .header("Authorization", "Bearer " + identityClientToken)
            .contentType(APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated()).andReturn();
        BaseClientDetails created = JsonUtils.readValue(result.getResponse().getContentAsString(), BaseClientDetails.class);
        assertNull(created.getClientSecret());
        assertEquals("zones.write", created.getAdditionalInformation().get(ClientConstants.CREATED_WITH));
        assertEquals(Collections.singletonList(Origin.UAA), created.getAdditionalInformation().get(ClientConstants.ALLOWED_PROVIDERS));
        assertEquals("bar", created.getAdditionalInformation().get("foo"));
        checkAuditEventListener(1, AuditEventType.ClientCreateSuccess, clientCreateEventListener, id, "http://localhost:8080/uaa/oauth/token", "identity");

        getMockMvc().perform(delete("/identity-zones/" + zone.getId() + "/clients/" + created.getClientId(), IdentityZone.getUaa().getId())
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
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(Origin.UAA));
        getMockMvc().perform(post("/identity-zones/uaa/clients")
            .header("Authorization", "Bearer " + identityClientToken)
            .contentType(APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isForbidden());
        assertEquals(0, clientCreateEventListener.getEventCount());

        getMockMvc().perform(delete("/identity-zones/uaa/clients/admin")
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
        getMockMvc().perform(post("/identity-zones/" + zone.getId() + "/clients")
            .header("Authorization", "Bearer " + identityClientToken)
            .contentType(APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isBadRequest());
    }

    private IdentityZone getIdentityZone(String id) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(StringUtils.hasText(id)?id:new RandomValueStringGenerator().generate());
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    @Test
    public void testCreateInvalidZone() throws Exception {
        IdentityZone identityZone = new IdentityZone();
        getMockMvc().perform(post("/identity-zones")
            .header("Authorization", "Bearer " + identityClientToken)
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(identityZone)))
            .andExpect(status().isBadRequest());

        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }



    @Test
    public void testCreatesZonesWithDuplicateSubdomains() throws Exception {
        String subdomain = UUID.randomUUID().toString();
        String id1 = UUID.randomUUID().toString();
        String id2 = UUID.randomUUID().toString();
        IdentityZone identityZone1 = MultitenancyFixture.identityZone(id1, subdomain);
        IdentityZone identityZone2 = MultitenancyFixture.identityZone(id2, subdomain);
        getMockMvc().perform(post("/identity-zones")
            .header("Authorization", "Bearer " + identityClientToken)
            .contentType(APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(identityZone1)))
            .andExpect(status().isCreated());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        getMockMvc().perform(post("/identity-zones")
            .header("Authorization", "Bearer " + identityClientToken)
            .contentType(APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(identityZone2)))
            .andExpect(status().isConflict());

        assertEquals(1, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testSuccessfulUserManagementInZoneUsingAdminClient() throws Exception {
        String subdomain = generator.generate();
        BaseClientDetails adminClient = new BaseClientDetails("admin", null, null, "client_credentials","scim.read,scim.write");
        adminClient.setClientSecret("admin-secret");
        IdentityZoneCreationResult creationResult = mockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), adminClient);
        IdentityZone identityZone = creationResult.getIdentityZone();

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);
        checkAuditEventListener(1, AuditEventType.GroupCreatedEvent, groupModifiedEventListener, IdentityZone.getUaa().getId(), "http://localhost:8080/uaa/oauth/token", "identity");
        checkAuditEventListener(1, AuditEventType.ClientCreateSuccess, clientCreateEventListener, identityZone.getId(), "http://localhost:8080/uaa/oauth/token", creationResult.getZoneAdminUser().getId());

        String zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write,scim.read", subdomain);
        ScimUser user = createUser(zoneAdminToken, subdomain);
        checkAuditEventListener(1, AuditEventType.UserCreatedEvent, userModifiedEventListener, identityZone.getId(), "http://"+subdomain+".localhost:8080/uaa/oauth/token", "admin");

        user.setUserName("updated-username@test.com");
        MockHttpServletRequestBuilder put = put("/Users/" + user.getId())
            .header("Authorization", "Bearer " + zoneAdminToken)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(user))
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        MvcResult result = getMockMvc().perform(put)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.userName").value(user.getUserName()))
            .andReturn();

        checkAuditEventListener(2, AuditEventType.UserModifiedEvent, userModifiedEventListener, identityZone.getId(), "http://"+subdomain+".localhost:8080/uaa/oauth/token", "admin");
        user = JsonUtils.readValue(result.getResponse().getContentAsString(), ScimUser.class);
        List<ScimUser> users = getUsersInZone(subdomain, zoneAdminToken);
        assertTrue(users.contains(user));
        assertEquals(1, users.size());

        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId())
            .header("Authorization", "Bearer " + zoneAdminToken)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON)
            .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        getMockMvc().perform(delete)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").value(user.getId()))
            .andReturn();

        checkAuditEventListener(3, AuditEventType.UserDeletedEvent, userModifiedEventListener, identityZone.getId(), "http://"+subdomain+".localhost:8080/uaa/oauth/token", "admin");
        users = getUsersInZone(subdomain, zoneAdminToken);
        assertEquals(0, users.size());
    }

    private List<ScimUser> getUsersInZone(String subdomain, String token) throws Exception {
        MockHttpServletRequestBuilder get = get("/Users").header("Authorization", "Bearer " + token);
        if (subdomain != null && !subdomain.equals("")) get.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        MvcResult mvcResult = getMockMvc().perform(get).andExpect(status().isOk()).andReturn();

        JsonNode root = JsonUtils.readTree(mvcResult.getResponse().getContentAsString());
        return JsonUtils.readValue(root.get("resources").toString(), new TypeReference<List<ScimUser>>() {
        });
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
        if (subdomain != null && !subdomain.equals("")) get.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        getMockMvc().perform(get).andExpect(status().isUnauthorized()).andReturn();
    }

    @Test
    public void testModifyandDeleteUserInOtherZoneIsUnauthorized() throws Exception {
        String defaultZoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        ScimUser user = createUser(defaultZoneAdminToken, null);

        String subdomain = generator.generate();
        mockMvcUtils.createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        String zoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write,scim.read", subdomain);
        user.setUserName("updated-user@defaultzone.com");

        MockHttpServletRequestBuilder put = put("/Users/" + user.getId())
            .header("Authorization", "Bearer " + zoneAdminToken)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(user));

        getMockMvc().perform(put)
            .andExpect(status().isUnauthorized())
            .andReturn();

        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId())
            .header("Authorization", "Bearer " + zoneAdminToken)
            .header("If-Match", "\"" + user.getVersion() + "\"")
            .contentType(APPLICATION_JSON);

        getMockMvc().perform(delete)
            .andExpect(status().isUnauthorized())
            .andReturn();
    }

    private IdentityZone getIdentityZone(String id, HttpStatus expect, String token) throws Exception {
        MvcResult result = getMockMvc().perform(get("/identity-zones/" + id)
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
        MvcResult result = getMockMvc().perform(post("/identity-zones")
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
        MvcResult result = getMockMvc().perform(put("/identity-zones/" + identityZone.getId())
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
            assertTrue(origin.contains("iss="+issuer));
            assertTrue(origin.contains("sub="+subject));
        }
    }
}
