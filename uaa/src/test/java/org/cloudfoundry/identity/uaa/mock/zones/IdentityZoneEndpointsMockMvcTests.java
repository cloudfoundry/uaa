package org.cloudfoundry.identity.uaa.mock.zones;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientCreateEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientDeleteEvent;
import org.cloudfoundry.identity.uaa.mfa_provider.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa_provider.MfaProvider;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.event.GroupModifiedEvent;
import org.cloudfoundry.identity.uaa.scim.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.KeyWithCertTest;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation.Banner;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MfaConfig;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneModifiedEvent;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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
import static org.springframework.util.StringUtils.hasText;

public class IdentityZoneEndpointsMockMvcTests extends InjectedMockContextTest {
    public static final List<String> BASE_URLS = Arrays.asList("/identity-zones", "/identity-zones/");

    private final String serviceProviderKey =
        "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXQIBAAKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5\n" +
            "L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vA\n" +
            "fpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQAB\n" +
            "AoGAVOj2Yvuigi6wJD99AO2fgF64sYCm/BKkX3dFEw0vxTPIh58kiRP554Xt5ges\n" +
            "7ZCqL9QpqrChUikO4kJ+nB8Uq2AvaZHbpCEUmbip06IlgdA440o0r0CPo1mgNxGu\n" +
            "lhiWRN43Lruzfh9qKPhleg2dvyFGQxy5Gk6KW/t8IS4x4r0CQQD/dceBA+Ndj3Xp\n" +
            "ubHfxqNz4GTOxndc/AXAowPGpge2zpgIc7f50t8OHhG6XhsfJ0wyQEEvodDhZPYX\n" +
            "kKBnXNHzAkEAyCA76vAwuxqAd3MObhiebniAU3SnPf2u4fdL1EOm92dyFs1JxyyL\n" +
            "gu/DsjPjx6tRtn4YAalxCzmAMXFSb1qHfwJBAM3qx3z0gGKbUEWtPHcP7BNsrnWK\n" +
            "vw6By7VC8bk/ffpaP2yYspS66Le9fzbFwoDzMVVUO/dELVZyBnhqSRHoXQcCQQCe\n" +
            "A2WL8S5o7Vn19rC0GVgu3ZJlUrwiZEVLQdlrticFPXaFrn3Md82ICww3jmURaKHS\n" +
            "N+l4lnMda79eSp3OMmq9AkA0p79BvYsLshUJJnvbk76pCjR28PK4dV1gSDUEqQMB\n" +
            "qy45ptdwJLqLJCeNoR0JUcDNIRhOCuOPND7pcMtX6hI/\n" +
            "-----END RSA PRIVATE KEY-----";

    private final String serviceProviderKeyPassword = "password";

    private final String serviceProviderCertificate =
        "-----BEGIN CERTIFICATE-----\n" +
            "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEO\n" +
            "MAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEO\n" +
            "MAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5h\n" +
            "cnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwx\n" +
            "CzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAM\n" +
            "BgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAb\n" +
            "BgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GN\n" +
            "ADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39W\n" +
            "qS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOw\n" +
            "znoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4Ha\n" +
            "MIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGc\n" +
            "gBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYD\n" +
            "VQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYD\n" +
            "VQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJh\n" +
            "QGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ\n" +
            "0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxC\n" +
            "KdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkK\n" +
            "RpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n" +
            "-----END CERTIFICATE-----\n";

    private String identityClientToken = null;
    private String identityClientZonesReadToken = null;
    private String identityClientZonesWriteToken = null;
    private String adminToken = null;
    private MockMvcUtils mockMvcUtils = MockMvcUtils.utils();
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private TestApplicationEventListener<IdentityZoneModifiedEvent> zoneModifiedEventListener;
    private TestApplicationEventListener<ClientCreateEvent> clientCreateEventListener;
    private TestApplicationEventListener<ClientDeleteEvent> clientDeleteEventListener;
    private TestApplicationEventListener<GroupModifiedEvent> groupModifiedEventListener;
    private TestApplicationEventListener<UserModifiedEvent> userModifiedEventListener;
    private TestApplicationEventListener<AbstractUaaEvent> uaaEventListener;
    private String lowPriviledgeToken;
    private JdbcIdentityZoneProvisioning provisioning;
    private BaseClientDetails uaaAdminClient;
    private ScimUser uaaAdminUser;
    private String uaaAdminClientToken;
    private String uaaAdminUserToken;

    @Before
    public void setUp() throws Exception {

        uaaAdminClient = new BaseClientDetails("uaa-admin-"+generator.generate().toLowerCase(),
                                               null,
                                               "uaa.admin",
                                               "password,client_credentials",
                                               "uaa.admin");
        uaaAdminClient.setClientSecret("secret");
        getWebApplicationContext().getBean(ClientRegistrationService.class).addClientDetails(uaaAdminClient);

        uaaAdminClientToken = testClient.getClientCredentialsOAuthAccessToken(
            uaaAdminClient.getClientId(),
            "secret",
            "uaa.admin");


        uaaAdminUser = createUser(uaaAdminClientToken, null);

        ScimGroupProvisioning groupProvisioning = getWebApplicationContext().getBean(ScimGroupProvisioning.class);
        ScimGroupMembershipManager membershipManager = getWebApplicationContext().getBean(ScimGroupMembershipManager.class);
        String groupId = groupProvisioning.getByName("uaa.admin", IdentityZone.getUaa().getId()).getId();
        membershipManager.addMember(groupId, new ScimGroupMember(uaaAdminUser.getId()), IdentityZone.getUaa().getId());


        uaaAdminUserToken = testClient.getUserOAuthAccessToken(
            uaaAdminClient.getClientId(),
            uaaAdminClient.getClientSecret(),
            uaaAdminUser.getUserName(),
            "password",
            "uaa.admin"
        );

        zoneModifiedEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), IdentityZoneModifiedEvent.class);
        clientCreateEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), ClientCreateEvent.class);
        clientDeleteEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), ClientDeleteEvent.class);
        groupModifiedEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), GroupModifiedEvent.class);
        userModifiedEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), UserModifiedEvent.class);
        uaaEventListener = mockMvcUtils.addEventListener(getWebApplicationContext(), AbstractUaaEvent.class);
        JdbcTemplate jdbcTemplate = getWebApplicationContext().getBean(JdbcTemplate.class);
        provisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);

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
        lowPriviledgeToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "scim.read");
        IdentityZoneHolder.clear();
        zoneModifiedEventListener.clearEvents();
        clientCreateEventListener.clearEvents();
        clientDeleteEventListener.clearEvents();
        groupModifiedEventListener.clearEvents();
        userModifiedEventListener.clearEvents();
    }

    @After
    public void after() throws Exception {
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
        user.setPassword("password");
        user.setUserName(email);
        user.setName(new ScimUser.Name("Joe", "User"));
        user.addEmail(email);
        return user;
    }

    public IdentityZone createZoneUsingToken(String token) throws Exception {
        return createZone(generator.generate().toLowerCase(),
                          HttpStatus.CREATED,
                          token,
                          new IdentityZoneConfiguration());
    }

    @Test
    public void create_zone_as_with_uaa_admin_client() throws Exception {
        createZoneUsingToken(uaaAdminClientToken);
    }

    @Test
    public void create_zone_as_with_uaa_admin_user() throws Exception {
        createZoneUsingToken(uaaAdminUserToken);
    }

    @Test
    public void read_zone_as_with_uaa_admin() throws Exception {
        IdentityZone zone = createZoneUsingToken(uaaAdminClientToken);
        for (String token : Arrays.asList(uaaAdminClientToken, uaaAdminUserToken)) {
            getMockMvc().perform(
                get("/identity-zones")
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", MediaType.APPLICATION_JSON_VALUE)
            )
                .andExpect(status().isOk());
            getMockMvc().perform(
                get("/identity-zones/{id}", zone.getId())
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", MediaType.APPLICATION_JSON_VALUE)
            )
                .andExpect(status().isOk());
        }
    }

    @Test
    public void update_zone_as_with_uaa_admin() throws Exception {
        IdentityZone zone = createZoneUsingToken(uaaAdminClientToken);
        for (String token : Arrays.asList(uaaAdminClientToken, uaaAdminUserToken)) {
            updateZone(zone, HttpStatus.OK, token);
        }
    }

    @Test
    public void create_zone_using_no_token() throws Exception {
        createZone(generator.generate().toLowerCase(),
                   HttpStatus.UNAUTHORIZED,
                   "",
                   new IdentityZoneConfiguration());
    }


    @Test
    public void delete_zone_as_with_uaa_admin() throws Exception {
        for (String token : Arrays.asList(uaaAdminClientToken, uaaAdminUserToken)) {
            IdentityZone zone = createZoneUsingToken(token);
            getMockMvc().perform(
                delete("/identity-zones/{id}", zone.getId())
                    .header("Authorization", "Bearer " + token)
                    .accept(APPLICATION_JSON))
                .andExpect(status().isOk());
        }
    }

    @Test
    public void readWithoutTokenShouldFail() throws Exception {
        for (String url : BASE_URLS) {
            getMockMvc().perform(get(url))
                .andExpect(status().isUnauthorized());
        }
    }

    @Test
    public void readWith_Write_TokenShouldNotFail() throws Exception {
        for (String url : BASE_URLS) {
            getMockMvc().perform(
                get(url)
                    .header("Authorization", "Bearer " + identityClientZonesWriteToken))
                .andExpect(status().isOk());
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
    public void create_zone_no_links() throws Exception {
        String id = generator.generate().toLowerCase();
        IdentityZoneConfiguration zoneConfiguration = new IdentityZoneConfiguration();
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, zoneConfiguration);
        assertNull(created.getConfig().getLinks().getHomeRedirect());
        assertNull(created.getConfig().getLinks().getSelfService().getSignup());
        assertNull(created.getConfig().getLinks().getSelfService().getPasswd());
        IdentityZone retrieved = getIdentityZone(id, HttpStatus.OK, identityClientToken);
        assertNull(retrieved.getConfig().getLinks().getHomeRedirect());
        assertNull(retrieved.getConfig().getLinks().getSelfService().getSignup());
        assertNull(retrieved.getConfig().getLinks().getSelfService().getPasswd());
    }

    @Test
    public void create_and_update_with_links() throws Exception {
        String id = generator.generate().toLowerCase();
        IdentityZoneConfiguration zoneConfiguration = new IdentityZoneConfiguration();
        zoneConfiguration.getLinks().setHomeRedirect("/home");
        zoneConfiguration.getLinks().getSelfService().setSignup("/signup");
        zoneConfiguration.getLinks().getSelfService().setPasswd("/passwd");
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, zoneConfiguration);
        assertEquals("/home", created.getConfig().getLinks().getHomeRedirect());
        assertEquals("/signup", created.getConfig().getLinks().getSelfService().getSignup());
        assertEquals("/passwd", created.getConfig().getLinks().getSelfService().getPasswd());
        IdentityZone retrieved = getIdentityZone(id, HttpStatus.OK, identityClientToken);
        assertEquals("/home", retrieved.getConfig().getLinks().getHomeRedirect());
        assertEquals("/signup", retrieved.getConfig().getLinks().getSelfService().getSignup());
        assertEquals("/passwd", retrieved.getConfig().getLinks().getSelfService().getPasswd());

        zoneConfiguration = created.getConfig();
        zoneConfiguration.getLinks().setHomeRedirect(null);
        zoneConfiguration.getLinks().getSelfService().setSignup(null);
        zoneConfiguration.getLinks().getSelfService().setPasswd(null);
        IdentityZone updated = updateZone(created, HttpStatus.OK, identityClientToken);
        assertNull(updated.getConfig().getLinks().getHomeRedirect());
        assertNull(updated.getConfig().getLinks().getSelfService().getSignup());
        assertNull(updated.getConfig().getLinks().getSelfService().getPasswd());
    }



    @Test
    public void testGetZoneAsIdentityClient() throws Exception {
        String id = generator.generate();
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        IdentityZone retrieved = getIdentityZone(id, HttpStatus.OK, identityClientToken);
        assertEquals(created.getId(), retrieved.getId());
        assertEquals(created.getName(), retrieved.getName());
        assertEquals(created.getSubdomain(), retrieved.getSubdomain());
        assertEquals(created.getDescription(), retrieved.getDescription());
    }

    @Test
    public void test_bootstrapped_system_scopes() throws Exception {
        String id = generator.generate();
        createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        List<String> groups = getWebApplicationContext().getBean(JdbcScimGroupProvisioning.class)
            .retrieveAll(id).stream().map(g -> g.getDisplayName()).collect(Collectors.toList());

        ZoneManagementScopes.getSystemScopes()
            .stream()
            .forEach(
                scope ->
                    assertTrue("Scope:" + scope + " should have been bootstrapped into the new zone", groups.contains(scope))
            );

    }


    @Test
    public void testGetZonesAsIdentityClient() throws Exception {
        String id = generator.generate();
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        getMockMvc().perform(
            get("/identity-zones/")
                .header("Authorization", "Bearer " + lowPriviledgeToken))
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
        createZoneReturn();
    }

    public IdentityZone createZoneReturn() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        assertEquals(id, zone.getId());
        assertEquals(id.toLowerCase(), zone.getSubdomain());
        assertFalse(zone.getConfig().getTokenPolicy().isRefreshTokenUnique());
        assertEquals(JWT.getStringValue(),zone.getConfig().getTokenPolicy().getRefreshTokenFormat());
        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent, zoneModifiedEventListener, IdentityZone.getUaa().getId(), "http://localhost:8080/uaa/oauth/token", "identity");

        //validate that default groups got created
        ScimGroupProvisioning groupProvisioning = getWebApplicationContext().getBean(ScimGroupProvisioning.class);
        for (String g : UserConfig.DEFAULT_ZONE_GROUPS) {
            assertNotNull(groupProvisioning.getByName(g, id));
        }
        return zone;
    }

    @Test
    public void updateZoneCreatesGroups() throws Exception {
        IdentityZone zone = createZoneReturn();
        List<String> zoneGroups = new LinkedList(zone.getConfig().getUserConfig().getDefaultGroups());

        //test two times with the same groups
        zone = updateZone(zone, HttpStatus.OK, identityClientToken);

        zoneGroups.add("updated.group.1");
        zoneGroups.add("updated.group.2");
        zone.getConfig().getUserConfig().setDefaultGroups(zoneGroups);
        zone = updateZone(zone, HttpStatus.OK, identityClientToken);

        //validate that default groups got created
        ScimGroupProvisioning groupProvisioning = getWebApplicationContext().getBean(ScimGroupProvisioning.class);
        for (String g : zoneGroups) {
            assertNotNull(groupProvisioning.getByName(g, zone.getId()));
        }
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
        createZone(id, HttpStatus.FORBIDDEN, lowPriviledgeToken, new IdentityZoneConfiguration());

        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testCreateZoneNoToken() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        createZone(id, HttpStatus.UNAUTHORIZED, "", new IdentityZoneConfiguration());

        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }


    @Test
    public void testCreateZoneWithoutID() throws Exception {
        IdentityZone zone = createZone("", HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        assertTrue(hasText(zone.getId()));
        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);
    }


    @Test
    public void testUpdateNonExistentReturns403() throws Exception {
        String id = new RandomValueStringGenerator().generate();
        IdentityZone identityZone = getIdentityZone(id);
        //zone doesn't exist and we don't have the token scope
        updateZone(identityZone, HttpStatus.FORBIDDEN, lowPriviledgeToken);

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

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        updateZone(created, HttpStatus.OK, identityClientToken);
        checkZoneAuditEventInUaa(2, AuditEventType.IdentityZoneModifiedEvent);
    }

    @Test
    public void testUpdateWithDifferentDataReturns200() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
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
    public void testCreateAndUpdateDoesNotReturnKeys() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        assertEquals(Collections.EMPTY_MAP, created.getConfig().getTokenPolicy().getKeys());
        assertEquals("kid", created.getConfig().getTokenPolicy().getActiveKeyId());
        assertNull(created.getConfig().getSamlConfig().getPrivateKey());
        assertNull(created.getConfig().getSamlConfig().getPrivateKeyPassword());
        assertNotNull(created.getConfig().getSamlConfig().getCertificate());
        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);
        created.setDescription("updated description");
        TokenPolicy tokenPolicy = new TokenPolicy(3600, 7200);
        HashMap<String, String> keys = new HashMap<>();
        keys.put("key1","value1");
        tokenPolicy.setKeys(keys);
        tokenPolicy.setActiveKeyId("key1");
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setCertificate(serviceProviderCertificate);
        samlConfig.setPrivateKey(serviceProviderKey);
        samlConfig.setPrivateKeyPassword(serviceProviderKeyPassword);
        IdentityZoneConfiguration definition = new IdentityZoneConfiguration(tokenPolicy);
        definition.setSamlConfig(samlConfig);
        created.setConfig(definition);

        IdentityZone updated = updateZone(created, HttpStatus.OK, identityClientToken);
        assertEquals("updated description", updated.getDescription());
        assertEquals(Collections.EMPTY_MAP, updated.getConfig().getTokenPolicy().getKeys());
        assertEquals("key1", updated.getConfig().getTokenPolicy().getActiveKeyId());
        assertNull(updated.getConfig().getSamlConfig().getPrivateKey());
        assertNull(updated.getConfig().getSamlConfig().getPrivateKeyPassword());
        assertEquals(serviceProviderCertificate, updated.getConfig().getSamlConfig().getCertificate());
    }

    @Test
    public void testUpdateIgnoresKeysWhenNotPresentInPayload() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        IdentityZone retrieve = provisioning.retrieve(created.getId());

        Map<String, String> keys = new HashMap<>();
        keys.put("kid", "key");

        assertEquals(keys.toString(), retrieve.getConfig().getTokenPolicy().getKeys().toString());

        created.setDescription("updated description");
        created.getConfig().getTokenPolicy().setKeys(null);
        IdentityZone updated = updateZone(created, HttpStatus.OK, identityClientToken);
        retrieve = provisioning.retrieve(created.getId());
        assertEquals(keys.toString(), retrieve.getConfig().getTokenPolicy().getKeys().toString());
    }

    @Test
    public void testUpdateWithInvalidSamlKeyCertPair() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        String samlPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "Proc-Type: 4,ENCRYPTED\n" +
            "DEK-Info: DES-EDE3-CBC,5771044F3450A262\n" +
            "\n" +
            "VfRgIdzq/TUFdIwTOxochDs02sSQXA/Z6mRnffYTQMwXpQ5f5nRuqcY8zECGMaDe\n" +
            "aLrndpWzGbxiePKgN5AxuIDYNnKMrDRgyCzaaPx66rb87oMwtuq1HM18qqs+yN5v\n" +
            "CdsoS2uz57fCDI24BuJkIDSIeumLXc5MdN0HUeaxOVzmpbpsbBXjRYa24gW38mUh\n" +
            "DzmOAsNDxfoSTox02Cj+GV024e+PiWR6AMA7RKhsKPf9F4ctWwozvEHrV8fzTy5B\n" +
            "+KM361P7XwJYueiV/gMZW2DXSujNRBEVfC1CLaxDV3eVsFX5iIiUbc4JQYOM6oQ3\n" +
            "KxGPImcRQPY0asKgEDIaWtysUuBoDSbfQ/FxGWeqwR6P/Vth4dXzVGheYLu1V1CU\n" +
            "o6M+EXC/VUhERKwi13EgqXLKrDI352/HgEKG60EhM6xIJy9hLHy0UGjdHDcA+cF6\n" +
            "NEl6E3CivddMHIPQWil5x4AMaevGa3v/gcZI0DN8t7L1g4fgjtSPYzvwmOxoxHGi\n" +
            "7V7PdzaD4GWV75fv99sBlq2e0KK9crNUzs7vbFA/m6tgNA628SGhU1uAc/5xOskI\n" +
            "0Ez6kjgHoh4U7t/fu7ey1MbFQt6byHY9lk27nW1ub/QMAaRJ+EDnrReB/NN6q5Vu\n" +
            "h9eQNniNOeQfflzFyPB9omLNsVJkENn+lZNNrrlbn8OmJ0pT58Iaetfh79rDZPw9\n" +
            "zmHVqmMynmecTWAcA9ATf7+lh+xV88JDjQkLcG/3WEXNH7HXKO00pUa8+JtyxbAb\n" +
            "dAwGgrjJkbbk1qLLScOqY4mA5WXa5+80LMkCYO44vVTp2VKmnxj8Mw==\n" +
            "-----END RSA PRIVATE KEY-----\n";
        String samlKeyPassphrase = "password";

        String samlCertificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEbzCCA1egAwIBAgIQCTPRC15ZcpIxJwdwiMVDSjANBgkqhkiG9w0BAQUFADA2\n" +
            "MQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\n" +
            "U1NMIENBMB4XDTEzMDczMDAwMDAwMFoXDTE2MDcyOTIzNTk1OVowPzEhMB8GA1UE\n" +
            "CxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRowGAYDVQQDExFlZHVyb2FtLmJi\n" +
            "ay5hYy51azCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANrSBWTl56O2\n" +
            "VJbahURgPznums43Nnn/smJ6cGywPu4mtJHUHSmONlBDTAWFS1fLkh8YHIQmdwYg\n" +
            "FY4pHjZmKVtJ6ZOFhDNN1R2VMka4ZtREWn3XX8pUacol5KjEIh6U/FvMHyRv7sV5\n" +
            "9J6JUK+n5R7ZsSu7XRi6TrT3xhfu0KoWo8RM/salKo2theIcyqLPHiFLEtA7ISLV\n" +
            "q7I49uj9h9Hni/iCpBey+Gn5yDub4nrv81aDfD6zDoW/vXIOrcXFYRK3lXWOOFi4\n" +
            "cfmu4SQQwMV1jBOer8JgfsQ3EQMgwauSMLUR31wPM83eMbOC72HhW9SJUtFDj42c\n" +
            "PIEWd+rTA8ECAwEAAaOCAW4wggFqMB8GA1UdIwQYMBaAFAy9k2gM896ro0lrKzdX\n" +
            "R+qQ47ntMB0GA1UdDgQWBBQgoU+Pbgk2MthczZt7TviUiIWyrjAOBgNVHQ8BAf8E\n" +
            "BAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH\n" +
            "AwIwIgYDVR0gBBswGTANBgsrBgEEAbIxAQICHTAIBgZngQwBAgEwOgYDVR0fBDMw\n" +
            "MTAvoC2gK4YpaHR0cDovL2NybC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5j\n" +
            "cmwwbQYIKwYBBQUHAQEEYTBfMDUGCCsGAQUFBzAChilodHRwOi8vY3J0LnRjcy50\n" +
            "ZXJlbmEub3JnL1RFUkVOQVNTTENBLmNydDAmBggrBgEFBQcwAYYaaHR0cDovL29j\n" +
            "c3AudGNzLnRlcmVuYS5vcmcwHAYDVR0RBBUwE4IRZWR1cm9hbS5iYmsuYWMudWsw\n" +
            "DQYJKoZIhvcNAQEFBQADggEBAHTw5b1lrTBqnx/QSO50Mww+OPYgV4b4NSu2rqxG\n" +
            "I2hHLiD4l7Sk3WOdXPAQMmTlo6N10Lt6p8gLLxKsOAw+nK+z9aLcgKk9/kYoe4C8\n" +
            "jHzwTy6eO+sCKnJfTqEX8p3b8l736lUWwPgMjjEN+d49ZegqCwH6SEz7h0+DwGmF\n" +
            "LLfFM8J1SozgPVXgmfCv0XHpFyYQPhXligeWk39FouC2DfhXDTDOgc0n/UQjETNl\n" +
            "r2Jawuw1VG6/+EFf4qjwr0/hIrxc/0XEd9+qLHKef1rMjb9pcZA7Dti+DoKHsxWi\n" +
            "yl3DnNZlj0tFP0SBcwjg/66VAekmFtJxsLx3hKxtYpO3m8c=\n" +
            "-----END CERTIFICATE-----\n";

        SamlConfig samlConfig = created.getConfig().getSamlConfig();
        samlConfig.setPrivateKey(samlPrivateKey);
        samlConfig.setPrivateKeyPassword(samlKeyPassphrase);
        samlConfig.setCertificate(samlCertificate);
        updateZone(created, HttpStatus.UNPROCESSABLE_ENTITY, identityClientToken);
    }

    @Test
    public void testUpdateWithPartialSamlKeyCertPair() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        SamlConfig samlConfig = created.getConfig().getSamlConfig();
        samlConfig.setPrivateKey(serviceProviderKey);
        samlConfig.setPrivateKeyPassword(null);
        samlConfig.setCertificate(serviceProviderCertificate);
        updateZone(created, HttpStatus.UNPROCESSABLE_ENTITY, identityClientToken);

        samlConfig = created.getConfig().getSamlConfig();
        samlConfig.setPrivateKey(null);
        samlConfig.setPrivateKeyPassword(serviceProviderKeyPassword);
        samlConfig.setCertificate(serviceProviderCertificate);
        updateZone(created, HttpStatus.UNPROCESSABLE_ENTITY, identityClientToken);
    }

    @Test
    public void testUpdateWithEmptySamlKeyCertPairRetainsCurrentValue() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        created.getConfig().getTokenPolicy().setKeys(new HashMap<>(Collections.singletonMap("kid", "key")));

        SamlConfig samlConfig = created.getConfig().getSamlConfig();


        samlConfig.setAssertionTimeToLiveSeconds(77);

        samlConfig.setPrivateKey(null);
        samlConfig.setPrivateKeyPassword(null);
        updateZone(created, HttpStatus.OK, identityClientToken);

        IdentityZone updated = provisioning.retrieve(created.getId());
        SamlConfig updatedSamlConfig = updated.getConfig().getSamlConfig();
        assertEquals(77, samlConfig.getAssertionTimeToLiveSeconds());
        assertEquals(serviceProviderCertificate, updatedSamlConfig.getCertificate());
        assertEquals(serviceProviderKey, updatedSamlConfig.getPrivateKey());
        assertEquals(serviceProviderKeyPassword, updatedSamlConfig.getPrivateKeyPassword());
    }

    @Test
    public void testUpdateWithNewSamlCertNoKeyIsUnprocessableEntity() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        SamlConfig samlConfig = created.getConfig().getSamlConfig();

        samlConfig.setAssertionTimeToLiveSeconds(77);

        samlConfig.setCertificate(KeyWithCertTest.invalidCert);
        samlConfig.setPrivateKey(null);
        samlConfig.setPrivateKeyPassword(null);
        updateZone(created, HttpStatus.UNPROCESSABLE_ENTITY, identityClientToken);
    }

    @Test
    public void testUpdateWithNewKeyNoCertIsUnprocessableEntity() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        SamlConfig samlConfig = created.getConfig().getSamlConfig();

        samlConfig.setAssertionTimeToLiveSeconds(77);

        samlConfig.setCertificate(null);
        samlConfig.setPrivateKey(serviceProviderKey);
        samlConfig.setPrivateKeyPassword(serviceProviderKeyPassword);
        updateZone(created, HttpStatus.UNPROCESSABLE_ENTITY, identityClientToken);
    }

    @Test
    public void testUpdateZoneWithExistingSubdomain() throws Exception {
        String id1 = generator.generate();
        IdentityZone created1 = createZone(id1, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        String id2 = generator.generate();
        IdentityZone created2 = createZone(id2, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
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
        updateZone(identityZone, HttpStatus.FORBIDDEN, lowPriviledgeToken);

        assertEquals(0, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testCreateDuplicateZoneReturns409() throws Exception {
        String id = generator.generate();
        createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        createZone(id, HttpStatus.CONFLICT, identityClientToken, new IdentityZoneConfiguration());

        assertEquals(1, zoneModifiedEventListener.getEventCount());
    }

    @Test
    public void testCreateZoneAndIdentityProvider() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = getIdentityZone(id);
        TokenPolicy tokenPolicy = new TokenPolicy(3600, 7200);
        Map<String, String> jwtKeys = new HashMap<>();
        jwtKeys.put("key_id_1", "secret_key_1");
        jwtKeys.put("key_id_2", "secret_key_2");
        tokenPolicy.setKeys(jwtKeys);
        tokenPolicy.setActiveKeyId("key_id_1");

        SamlConfig samlConfig = new SamlConfig();

        String samlPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXAIBAAKBgQCpnqPQiDCfJY1hVaQUZG6Rs1Wd3FmP1EStN71hXeXOLog5nvpa\n" +
            "H45P3v79EGpaO06vH5qSu/xr6kQRBOA4h9OqXGS72BGQBH8jMNCoHqgJrIADQTHX\n" +
            "H85RYF38bH6Ycp18jch0KVmYwKeiaLNfMDngnAv6wMDONJz761GBtrG1/wIDAQAB\n" +
            "AoGAPjYeNSzOUICwcyO7E3Omji/tVgHso3EiYznPbvfGgrHUavXhMs7iHm9WrLCp\n" +
            "oUChYl/ADNOACICayHc2WeWPfxJ26BF0ahTzOX1fJsg++JDweCYCNN2WrrYcyA9o\n" +
            "XDU18IFh2dY2CvPL8G7ex5WEq9nYTASQzRfC899nTvUSTyECQQDZddRhqF9g6Zc9\n" +
            "vuSjwQf+dMztsvhLVPAPaSdgE4LMa4nE2iNC/sLq1uUEwrrrOKGaFB9IXeIU7hPW\n" +
            "2QmgJewxAkEAx65IjpesMEq+zE5qRPYkfxjdaa0gNBCfATEBGI4bTx37cKskf49W\n" +
            "2qFlombE9m9t/beYXVC++2W40i53ov+pLwJALRp0X4EFr1sjxGnIkHJkDxH4w0CA\n" +
            "oVdPp1KfGR1S3sVbQNohwC6JDR5fR/p/vHP1iLituFvInaC3urMvfOkAsQJBAJg9\n" +
            "0gYdr+O16Vi95JoljNf2bkG3BJmNnp167ln5ZurgcieJ5K7464CPk3zJnBxEAvlx\n" +
            "dFKZULM98DcXxJFbGXMCQC2ZkPFgzMlRwYu4gake2ruOQR9N3HzLoau1jqDrgh6U\n" +
            "Ow3ylw8RWPq4zmLkDPn83DFMBquYsg3yzBPi7PANBO4=\n" +
            "-----END RSA PRIVATE KEY-----\n";
        String samlKeyPassphrase = "password";

        String samlCertificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIID4zCCA0ygAwIBAgIJAJdmwmBdhEydMA0GCSqGSIb3DQEBBQUAMIGoMQswCQYD\n" +
            "VQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xJzAl\n" +
            "BgNVBAoTHkNsb3VkIEZvdW5kcnkgRm91bmRhdGlvbiwgSW5jLjEMMAoGA1UECxMD\n" +
            "VUFBMRIwEAYDVQQDEwlsb2NhbGhvc3QxKTAnBgkqhkiG9w0BCQEWGmNmLWlkZW50\n" +
            "aXR5LWVuZ0BwaXZvdGFsLmlvMB4XDTE2MDIxNjIyMTMzN1oXDTE2MDMxNzIyMTMz\n" +
            "N1owgagxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZy\n" +
            "YW5jaXNjbzEnMCUGA1UEChMeQ2xvdWQgRm91bmRyeSBGb3VuZGF0aW9uLCBJbmMu\n" +
            "MQwwCgYDVQQLEwNVQUExEjAQBgNVBAMTCWxvY2FsaG9zdDEpMCcGCSqGSIb3DQEJ\n" +
            "ARYaY2YtaWRlbnRpdHktZW5nQHBpdm90YWwuaW8wgZ8wDQYJKoZIhvcNAQEBBQAD\n" +
            "gY0AMIGJAoGBAKmeo9CIMJ8ljWFVpBRkbpGzVZ3cWY/URK03vWFd5c4uiDme+lof\n" +
            "jk/e/v0Qalo7Tq8fmpK7/GvqRBEE4DiH06pcZLvYEZAEfyMw0KgeqAmsgANBMdcf\n" +
            "zlFgXfxsfphynXyNyHQpWZjAp6Jos18wOeCcC/rAwM40nPvrUYG2sbX/AgMBAAGj\n" +
            "ggERMIIBDTAdBgNVHQ4EFgQUdiixDfiZ61ljk7J/uUYcay26n5swgd0GA1UdIwSB\n" +
            "1TCB0oAUdiixDfiZ61ljk7J/uUYcay26n5uhga6kgaswgagxCzAJBgNVBAYTAlVT\n" +
            "MQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEnMCUGA1UEChMe\n" +
            "Q2xvdWQgRm91bmRyeSBGb3VuZGF0aW9uLCBJbmMuMQwwCgYDVQQLEwNVQUExEjAQ\n" +
            "BgNVBAMTCWxvY2FsaG9zdDEpMCcGCSqGSIb3DQEJARYaY2YtaWRlbnRpdHktZW5n\n" +
            "QHBpdm90YWwuaW+CCQCXZsJgXYRMnTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB\n" +
            "BQUAA4GBAAPf/SPl/LuVYrl0HDUU8YDR3N7Fi4OjhF3+n+uBYRhO+9IbQ/t1sC1p\n" +
            "enWhiAfyZtgFv2OmjvtFyty9YqHhIPAg9Ceod37Q7HNSG04vbYHNJ6XhGUzacMj8\n" +
            "hQ1ZzQBv+CaKWZarBIql/TsxtpvvXhaE4QqR4NvUDnESHtxefriv\n" +
            "-----END CERTIFICATE-----\n";

        samlConfig.setCertificate(samlCertificate);
        samlConfig.setPrivateKey(samlPrivateKey);
        samlConfig.setPrivateKeyPassword(samlKeyPassphrase);

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
        assertEquals(samlCertificate, createdZone.getConfig().getSamlConfig().getCertificate());
        assertEquals(samlPrivateKey, createdZone.getConfig().getSamlConfig().getPrivateKey());
    }

    @Test
    public void testCreateZoneWithInvalidPrimarySigningKeyId() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = getIdentityZone(id);
        TokenPolicy tokenPolicy = identityZone.getConfig().getTokenPolicy();
        Map<String, String> jwtKeys = new HashMap<>();
        jwtKeys.put("key_id_1", "secret_key_1");
        jwtKeys.put("key_id_2", "secret_key_2");
        tokenPolicy.setKeys(jwtKeys);
        tokenPolicy.setActiveKeyId("nonexistent_key");

        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
            .andExpect(status().isUnprocessableEntity());
    }

    @Test
    public void testCreateZoneWithNoActiveKeyId() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = getIdentityZone(id);
        TokenPolicy tokenPolicy = identityZone.getConfig().getTokenPolicy();
        Map<String, String> jwtKeys = new HashMap<>();
        jwtKeys.put("key_id_1", "secret_key_1");
        jwtKeys.put("key_id_2", "secret_key_2");
        jwtKeys.put("key_id_3", "secret_key_3");
        tokenPolicy.setKeys(jwtKeys);

        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
            .andExpect(status().isCreated());
    }

    @Test
    public void testCreateZoneWithRefreshTokenConfig() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = getIdentityZone(id);
        TokenPolicy tokenPolicy = identityZone.getConfig().getTokenPolicy();
        tokenPolicy.setRefreshTokenFormat(OPAQUE.getStringValue().toUpperCase());
        tokenPolicy.setRefreshTokenUnique(true);

        getMockMvc().perform(
                post("/identity-zones")
                        .header("Authorization", "Bearer " + identityClientToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.config.tokenPolicy.refreshTokenUnique").value(true))
                .andExpect(jsonPath("$.config.tokenPolicy.refreshTokenFormat").value(OPAQUE.getStringValue()));


        IdentityZone createdZone = provisioning.retrieve(id);
        assertEquals(OPAQUE.getStringValue(), createdZone.getConfig().getTokenPolicy().getRefreshTokenFormat());
        assertTrue(createdZone.getConfig().getTokenPolicy().isRefreshTokenUnique());
    }

    @Test
    public void testCreateZoneWithCustomBrandingBanner() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = getIdentityZone(id);
        Banner banner = new Banner();
        String backgroundColor = "#112233";
        String link = "http://example.com";
        String text = "My Banner";
        banner.setBackgroundColor(backgroundColor);
        banner.setLink(link);
        banner.setText(text);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        String contentAsString = getMockMvc().perform(
                post("/identity-zones")
                        .header("Authorization", "Bearer " + identityClientToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(zone)))
                .andReturn().getResponse().getContentAsString();
        IdentityZone createdZone = JsonUtils.readValue(contentAsString, IdentityZone.class);

        Banner zoneBanner = createdZone.getConfig().getBranding().getBanner();
        assertEquals(text, zoneBanner.getText());
        assertEquals(link, zoneBanner.getLink());
        assertEquals(backgroundColor, zoneBanner.getBackgroundColor());
    }

    @Test
    public void testCreateZoneWithIncorrectBrandingBannerLink() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = getIdentityZone(id);
        Banner banner = new Banner();
        String backgroundColor = "#112233";
        String invalidUrl = "this_is_an_invalid_url";
        banner.setBackgroundColor(backgroundColor);
        banner.setLink(invalidUrl);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        MockHttpServletResponse response = getMockMvc().perform(
                post("/identity-zones")
                        .header("Authorization", "Bearer " + identityClientToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn().getResponse();

        assertThat(response.getContentAsString(), containsString("Invalid banner link: " + invalidUrl + ". Must be a properly formatted URI beginning with http:// or https://"));
    }

    @Test
    public void testUpdateZoneWithIncorrectBrandingBannerLink() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = getIdentityZone(id);
        Banner banner = new Banner();
        String backgroundColor = "#112233";
        String validUrl = "http://example.com";
        banner.setBackgroundColor(backgroundColor);
        banner.setLink(validUrl);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        String response = getMockMvc().perform(
                post("/identity-zones")
                        .header("Authorization", "Bearer " + identityClientToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        IdentityZone createdZone = JsonUtils.readValue(response, IdentityZone.class);
        String invalidUrl = "this_is_an_invalid_url";
        createdZone.getConfig().getBranding().getBanner().setLink(invalidUrl);

        MockHttpServletResponse mvcResult = getMockMvc().perform(
                put("/identity-zones/" + createdZone.getId())
                        .header("Authorization", "Bearer " + identityClientToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(createdZone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn()
                .getResponse();

        assertThat(mvcResult.getContentAsString(), containsString("Invalid banner link: " + invalidUrl + ". Must be a properly formatted URI beginning with http:// or https://"));
    }


    @Test
    public void testCreateZoneWithInvalidBannerBackgroundColor() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = getIdentityZone(id);
        Banner banner = new Banner();
        String invalidColor = "#ZLKSWE";
        String validUrl = "http://example.com";
        banner.setBackgroundColor(invalidColor);
        banner.setLink(validUrl);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        MockHttpServletResponse mvcResult = getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(zone)))
            .andExpect(status().isUnprocessableEntity())
            .andReturn().getResponse();

        assertThat(mvcResult.getContentAsString(), containsString("Invalid banner background color: " + invalidColor + ". Must be a properly formatted hexadecimal color code."));
    }

    @Test
    public void testUpdateZoneWithInvalidBannerBackgroundColor() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = getIdentityZone(id);
        Banner banner = new Banner();
        String backgroundColor = "#112233";
        String validUrl = "http://example.com";
        banner.setBackgroundColor(backgroundColor);
        banner.setLink(validUrl);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        String response = getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(zone)))
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsString();

        IdentityZone createdZone = JsonUtils.readValue(response, IdentityZone.class);
        String invalidColor = "#ZLKSWE";
        createdZone.getConfig().getBranding().getBanner().setBackgroundColor(invalidColor);

        MockHttpServletResponse mvcResult = getMockMvc().perform(
            put("/identity-zones/" + createdZone.getId())
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(createdZone)))
            .andExpect(status().isUnprocessableEntity())
            .andReturn()
            .getResponse();

        assertThat(mvcResult.getContentAsString(), containsString("Invalid banner background color: " + invalidColor + ". Must be a properly formatted hexadecimal color code."));
    }

    @Test
    public void testCreateZoneWithInvalidBannerTextColor() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = getIdentityZone(id);
        Banner banner = new Banner();
        String invalidColor = "#ZLKSWE";
        String validUrl = "http://example.com";
        banner.setTextColor(invalidColor);
        banner.setLink(validUrl);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        MockHttpServletResponse mvcResult = getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(zone)))
            .andExpect(status().isUnprocessableEntity())
            .andReturn().getResponse();

        assertThat(mvcResult.getContentAsString(), containsString("Invalid banner text color: " + invalidColor + ". Must be a properly formatted hexadecimal color code."));
    }

    @Test
    public void testUpdateZoneWithInvalidBannerTextColor() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = getIdentityZone(id);
        Banner banner = new Banner();
        String textColor = "#112233";
        String validUrl = "http://example.com";
        banner.setTextColor(textColor);
        banner.setLink(validUrl);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        String response = getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(zone)))
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsString();

        IdentityZone createdZone = JsonUtils.readValue(response, IdentityZone.class);
        String invalidColor = "#ZLKSWE";
        createdZone.getConfig().getBranding().getBanner().setTextColor(invalidColor);

        MockHttpServletResponse mvcResult = getMockMvc().perform(
            put("/identity-zones/" + createdZone.getId())
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(createdZone)))
            .andExpect(status().isUnprocessableEntity())
            .andReturn()
            .getResponse();

        assertThat(mvcResult.getContentAsString(), containsString("Invalid banner text color: " + invalidColor + ". Must be a properly formatted hexadecimal color code."));
    }

    @Test
    public void testCreateZoneWithInvalidBannerLogo() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = getIdentityZone(id);
        Banner banner = new Banner();
        String textColor = "#112233";
        String validUrl = "http://example.com";
        banner.setTextColor(textColor);
        banner.setLink(validUrl);
        banner.setLogo("NOT_BASE_64%");
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        MockHttpServletResponse mvcResult = getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(zone)))
            .andExpect(status().isUnprocessableEntity())
            .andReturn().getResponse();

        assertThat(mvcResult.getContentAsString(), containsString("Invalid banner logo. Must be in BASE64 format."));
    }

    @Test
    public void testUpdateZoneWithInvalidBannerLogo() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = getIdentityZone(id);
        Banner banner = new Banner();
        String textColor = "#112233";
        String validUrl = "http://example.com";
        banner.setTextColor(textColor);
        banner.setLink(validUrl);
        banner.setLogo("VALIDBASE64");

        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        String response = getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(zone)))
            .andExpect(status().isCreated())
            .andReturn().getResponse().getContentAsString();

        IdentityZone createdZone = JsonUtils.readValue(response, IdentityZone.class);
        String invalidLogo = "INVALID_BASE_64%";
        createdZone.getConfig().getBranding().getBanner().setLogo(invalidLogo);

        MockHttpServletResponse mvcResult = getMockMvc().perform(
            put("/identity-zones/" + createdZone.getId())
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(createdZone)))
            .andExpect(status().isUnprocessableEntity())
            .andReturn()
            .getResponse();

        assertThat(mvcResult.getContentAsString(), containsString("Invalid banner logo. Must be in BASE64 format."));
    }

    @Test
    public void testCreateZoneWithInvalidSamlKeyCertPair() throws Exception {

        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = getIdentityZone(id);
        TokenPolicy tokenPolicy = new TokenPolicy(3600, 7200);
        Map<String, String> jwtKeys = new HashMap<>();
        jwtKeys.put("key_id_1", "secret_key_1");
        jwtKeys.put("key_id_2", "secret_key_2");
        tokenPolicy.setKeys(jwtKeys);
        tokenPolicy.setActiveKeyId("key_id_1");

        SamlConfig samlConfig = new SamlConfig();

        String samlPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "Proc-Type: 4,ENCRYPTED\n" +
            "DEK-Info: DES-EDE3-CBC,5771044F3450A262\n" +
            "\n" +
            "VfRgIdzq/TUFdIwTOxochDs02sSQXA/Z6mRnffYTQMwXpQ5f5nRuqcY8zECGMaDe\n" +
            "aLrndpWzGbxiePKgN5AxuIDYNnKMrDRgyCzaaPx66rb87oMwtuq1HM18qqs+yN5v\n" +
            "CdsoS2uz57fCDI24BuJkIDSIeumLXc5MdN0HUeaxOVzmpbpsbBXjRYa24gW38mUh\n" +
            "DzmOAsNDxfoSTox02Cj+GV024e+PiWR6AMA7RKhsKPf9F4ctWwozvEHrV8fzTy5B\n" +
            "+KM361P7XwJYueiV/gMZW2DXSujNRBEVfC1CLaxDV3eVsFX5iIiUbc4JQYOM6oQ3\n" +
            "KxGPImcRQPY0asKgEDIaWtysUuBoDSbfQ/FxGWeqwR6P/Vth4dXzVGheYLu1V1CU\n" +
            "o6M+EXC/VUhERKwi13EgqXLKrDI352/HgEKG60EhM6xIJy9hLHy0UGjdHDcA+cF6\n" +
            "NEl6E3CivddMHIPQWil5x4AMaevGa3v/gcZI0DN8t7L1g4fgjtSPYzvwmOxoxHGi\n" +
            "7V7PdzaD4GWV75fv99sBlq2e0KK9crNUzs7vbFA/m6tgNA628SGhU1uAc/5xOskI\n" +
            "0Ez6kjgHoh4U7t/fu7ey1MbFQt6byHY9lk27nW1ub/QMAaRJ+EDnrReB/NN6q5Vu\n" +
            "h9eQNniNOeQfflzFyPB9omLNsVJkENn+lZNNrrlbn8OmJ0pT58Iaetfh79rDZPw9\n" +
            "zmHVqmMynmecTWAcA9ATf7+lh+xV88JDjQkLcG/3WEXNH7HXKO00pUa8+JtyxbAb\n" +
            "dAwGgrjJkbbk1qLLScOqY4mA5WXa5+80LMkCYO44vVTp2VKmnxj8Mw==\n" +
            "-----END RSA PRIVATE KEY-----\n";
        String samlKeyPassphrase = "password";

        String samlCertificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEbzCCA1egAwIBAgIQCTPRC15ZcpIxJwdwiMVDSjANBgkqhkiG9w0BAQUFADA2\n" +
            "MQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg\n" +
            "U1NMIENBMB4XDTEzMDczMDAwMDAwMFoXDTE2MDcyOTIzNTk1OVowPzEhMB8GA1UE\n" +
            "CxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRowGAYDVQQDExFlZHVyb2FtLmJi\n" +
            "ay5hYy51azCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANrSBWTl56O2\n" +
            "VJbahURgPznums43Nnn/smJ6cGywPu4mtJHUHSmONlBDTAWFS1fLkh8YHIQmdwYg\n" +
            "FY4pHjZmKVtJ6ZOFhDNN1R2VMka4ZtREWn3XX8pUacol5KjEIh6U/FvMHyRv7sV5\n" +
            "9J6JUK+n5R7ZsSu7XRi6TrT3xhfu0KoWo8RM/salKo2theIcyqLPHiFLEtA7ISLV\n" +
            "q7I49uj9h9Hni/iCpBey+Gn5yDub4nrv81aDfD6zDoW/vXIOrcXFYRK3lXWOOFi4\n" +
            "cfmu4SQQwMV1jBOer8JgfsQ3EQMgwauSMLUR31wPM83eMbOC72HhW9SJUtFDj42c\n" +
            "PIEWd+rTA8ECAwEAAaOCAW4wggFqMB8GA1UdIwQYMBaAFAy9k2gM896ro0lrKzdX\n" +
            "R+qQ47ntMB0GA1UdDgQWBBQgoU+Pbgk2MthczZt7TviUiIWyrjAOBgNVHQ8BAf8E\n" +
            "BAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH\n" +
            "AwIwIgYDVR0gBBswGTANBgsrBgEEAbIxAQICHTAIBgZngQwBAgEwOgYDVR0fBDMw\n" +
            "MTAvoC2gK4YpaHR0cDovL2NybC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5j\n" +
            "cmwwbQYIKwYBBQUHAQEEYTBfMDUGCCsGAQUFBzAChilodHRwOi8vY3J0LnRjcy50\n" +
            "ZXJlbmEub3JnL1RFUkVOQVNTTENBLmNydDAmBggrBgEFBQcwAYYaaHR0cDovL29j\n" +
            "c3AudGNzLnRlcmVuYS5vcmcwHAYDVR0RBBUwE4IRZWR1cm9hbS5iYmsuYWMudWsw\n" +
            "DQYJKoZIhvcNAQEFBQADggEBAHTw5b1lrTBqnx/QSO50Mww+OPYgV4b4NSu2rqxG\n" +
            "I2hHLiD4l7Sk3WOdXPAQMmTlo6N10Lt6p8gLLxKsOAw+nK+z9aLcgKk9/kYoe4C8\n" +
            "jHzwTy6eO+sCKnJfTqEX8p3b8l736lUWwPgMjjEN+d49ZegqCwH6SEz7h0+DwGmF\n" +
            "LLfFM8J1SozgPVXgmfCv0XHpFyYQPhXligeWk39FouC2DfhXDTDOgc0n/UQjETNl\n" +
            "r2Jawuw1VG6/+EFf4qjwr0/hIrxc/0XEd9+qLHKef1rMjb9pcZA7Dti+DoKHsxWi\n" +
            "yl3DnNZlj0tFP0SBcwjg/66VAekmFtJxsLx3hKxtYpO3m8c=\n" +
            "-----END CERTIFICATE-----\n";

        samlConfig.setCertificate(samlCertificate);
        samlConfig.setPrivateKey(samlPrivateKey);
        samlConfig.setPrivateKeyPassword(samlKeyPassphrase);

        IdentityZoneConfiguration definition = new IdentityZoneConfiguration(tokenPolicy);
        identityZone.setConfig(definition.setSamlConfig(samlConfig));

        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + identityClientToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(identityZone)))
            .andExpect(status().isUnprocessableEntity());
    }

    @Test
    public void test_delete_zone_cleans_db() throws Exception {
        IdentityProviderProvisioning idpp = getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class);
        ScimGroupProvisioning groupProvisioning = getWebApplicationContext().getBean(ScimGroupProvisioning.class);
        ScimUserProvisioning userProvisioning = getWebApplicationContext().getBean(ScimUserProvisioning.class);
        ScimGroupMembershipManager membershipManager = getWebApplicationContext().getBean(ScimGroupMembershipManager.class);
        ScimGroupExternalMembershipManager externalMembershipManager = getWebApplicationContext().getBean(ScimGroupExternalMembershipManager.class);
        ApprovalStore approvalStore = getWebApplicationContext().getBean(ApprovalStore.class);
        JdbcTemplate template = getWebApplicationContext().getBean(JdbcTemplate.class);

        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        //create zone and clients
        BaseClientDetails client = new BaseClientDetails("limited-client", null, "openid", "authorization_code",
                                                         "uaa.resource");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(UAA));
        client.addAdditionalInformation("foo", "bar");
        for (String url : Arrays.asList("", "/")) {
            getMockMvc().perform(
                post("/identity-zones/" + zone.getId() + "/clients" + url)
                    .header("Authorization", "Bearer " + identityClientZonesReadToken)
                    .contentType(APPLICATION_JSON)
                    .accept(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isForbidden());
        }

        //create client without token
        getMockMvc().perform(post("/identity-zones/" + zone.getId() + "/clients")
            .contentType(APPLICATION_JSON)
            .accept(APPLICATION_JSON)
            .content(JsonUtils.writeValueAsString(client)))
            .andExpect(status().isUnauthorized());

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
        provider = idpp.create(provider, provider.getIdentityZoneId());
        assertNotNull(idpp.retrieveByOrigin(LOGIN_SERVER, zone.getId()));
        assertEquals(provider.getId(), idpp.retrieveByOrigin(LOGIN_SERVER, zone.getId()).getId());

        //create user and add user to group
        ScimUser user = getScimUser();
        user.setOrigin(LOGIN_SERVER);
        user = userProvisioning.createUser(user, "", IdentityZoneHolder.get().getId());
        assertNotNull(userProvisioning.retrieve(user.getId(), IdentityZoneHolder.get().getId()));
        assertEquals(zone.getId(), user.getZoneId());

        //create group
        ScimGroup group = new ScimGroup("Delete Test Group");
        group.setZoneId(zone.getId());
        group = groupProvisioning.create(group, IdentityZoneHolder.get().getId());
        membershipManager.addMember(group.getId(), new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER), IdentityZoneHolder.get().getId());
        assertEquals(zone.getId(), group.getZoneId());
        assertNotNull(groupProvisioning.retrieve(group.getId(), IdentityZoneHolder.get().getId()));
        assertEquals("Delete Test Group", groupProvisioning.retrieve(group.getId(), IdentityZoneHolder.get().getId()).getDisplayName());
        assertEquals(1, membershipManager.getMembers(group.getId(), false, IdentityZoneHolder.get().getId()).size());

        //failed authenticated user
        getMockMvc().perform(
            post("/login.do")
                .header("Host", zone.getSubdomain() + ".localhost")
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
        ScimGroupExternalMember externalMember = externalMembershipManager.mapExternalGroup(group.getId(), "externalDeleteGroup", LOGIN_SERVER, IdentityZoneHolder.get().getId());
        assertEquals(1, externalMembershipManager.getExternalGroupMapsByGroupId(group.getId(), LOGIN_SERVER, IdentityZoneHolder.get().getId()).size());
        assertThat(template.queryForObject("select count(*) from external_group_mapping where origin=?", new Object[]{LOGIN_SERVER}, Integer.class), is(1));

        //add user approvals
        approvalStore.addApproval(
            new Approval()
                .setClientId(client.getClientId())
                .setScope("openid")
                .setStatus(Approval.ApprovalStatus.APPROVED)
                .setUserId(user.getId()), IdentityZoneHolder.get().getId()
        );
        assertEquals(1, approvalStore.getApprovals(user.getId(), client.getClientId(), IdentityZoneHolder.get().getId()).size());

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

        assertThat(template.queryForObject("select count(*) from identity_zone where id=?", new Object[]{zone.getId()}, Integer.class), is(0));

        assertThat(template.queryForObject("select count(*) from oauth_client_details where identity_zone_id=?", new Object[]{zone.getId()}, Integer.class), is(0));

        assertThat(template.queryForObject("select count(*) from groups where identity_zone_id=?", new Object[]{zone.getId()}, Integer.class), is(0));

        assertThat(template.queryForObject("select count(*) from sec_audit where identity_zone_id=?", new Object[]{zone.getId()}, Integer.class), is(0));

        assertThat(template.queryForObject("select count(*) from users where identity_zone_id=?", new Object[]{zone.getId()}, Integer.class), is(0));

        assertThat(template.queryForObject("select count(*) from external_group_mapping where origin=?", new Object[]{LOGIN_SERVER}, Integer.class), is(0));
        try {
            externalMembershipManager.getExternalGroupMapsByGroupId(group.getId(), LOGIN_SERVER, IdentityZoneHolder.get().getId());
            fail("no external groups should be found");
        } catch (ScimResourceNotFoundException e) {
        }

        assertThat(template.queryForObject("select count(*) from authz_approvals where user_id=?", new Object[]{user.getId()}, Integer.class), is(0));
        assertEquals(0, approvalStore.getApprovals(user.getId(), client.getClientId(), IdentityZoneHolder.get().getId()).size());


    }

    @Test
    public void testDeleteZonePublishesEvent() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        uaaEventListener.clearEvents();

        ResultActions result = getMockMvc().perform(
                delete("/identity-zones/{id}", zone.getId())
                        .header("Authorization", "Bearer " + identityClientToken)
                        .accept(APPLICATION_JSON))
                .andExpect(status().isOk());
        IdentityZone deletedZone = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), IdentityZone.class);
        assertEquals(Collections.EMPTY_MAP, deletedZone.getConfig().getTokenPolicy().getKeys());
        assertNull(deletedZone.getConfig().getSamlConfig().getPrivateKey());
        assertNull(deletedZone.getConfig().getSamlConfig().getPrivateKeyPassword());
        assertEquals(serviceProviderCertificate, deletedZone.getConfig().getSamlConfig().getCertificate());

        assertThat(uaaEventListener.getEventCount(), is(1));
        AbstractUaaEvent event = uaaEventListener.getLatestEvent();
        assertThat(event, instanceOf(EntityDeletedEvent.class));
        EntityDeletedEvent deletedEvent = (EntityDeletedEvent) event;
        assertThat(deletedEvent.getDeleted(), instanceOf(IdentityZone.class));

        deletedZone = (IdentityZone) deletedEvent.getDeleted();
        assertThat(deletedZone.getId(), is(id));
        assertThat(deletedEvent.getIdentityZone().getId(), is(id));
        String auditedIdentityZone = deletedEvent.getAuditEvent().getData();
        assertThat(auditedIdentityZone, containsString(id));
    }

    @Test
    public void testCreateAndDeleteLimitedClientInNewZoneUsingZoneEndpoint() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        BaseClientDetails client = new BaseClientDetails("limited-client", null, "openid", "authorization_code",
                                                         "uaa.resource");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(UAA));
        client.addAdditionalInformation("foo", "bar");
        for (String url : Arrays.asList("", "/")) {
            getMockMvc().perform(
                post("/identity-zones/" + zone.getId() + "/clients" + url)
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

        for (String url : Arrays.asList("", "/")) {
            getMockMvc().perform(
                delete("/identity-zones/" + zone.getId() + "/clients/" + created.getClientId(), IdentityZone.getUaa().getId() + url)
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
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
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
                .header(IdentityZoneSwitchingFilter.HEADER, result1.getIdentityZone().getId())
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
                .header(IdentityZoneSwitchingFilter.HEADER, result1.getIdentityZone().getId())
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(result1.getIdentityZone())))
            .andExpect(status().isOk());

        //test write someone elses
        getMockMvc().perform(
            put("/identity-zones/" + result2.getIdentityZone().getId())
                .header("Authorization", "Bearer " + result1.getZoneAdminToken())
                .header(IdentityZoneSwitchingFilter.HEADER, result1.getIdentityZone().getId())
                .contentType(APPLICATION_JSON)
                .accept(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(result2.getIdentityZone())))
            .andExpect(status().isForbidden());

        //test create as zone admin
        getMockMvc().perform(
            post("/identity-zones")
                .header("Authorization", "Bearer " + result1.getZoneAdminToken())
                .header(IdentityZoneSwitchingFilter.HEADER, result1.getIdentityZone().getId())
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
        IdentityZone identityZone = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        for (String displayName : Arrays.asList("read", "admin")) {
            ScimGroup group = new ScimGroup();
            String zoneReadScope = "zones." + identityZone.getId() + "." + displayName;
            group.setDisplayName(zoneReadScope);
            group.setMembers(Collections.singletonList(new ScimGroupMember(user.getId())));
            getMockMvc().perform(
                post("/Groups/zones")
                    .header("Authorization", "Bearer " + identityClientToken)
                    .contentType(APPLICATION_JSON)
                    .accept(APPLICATION_JSON)
                    .content(JsonUtils.writeValueAsString(group)))
                .andExpect(status().isCreated());
        }

        String userAccessToken = mockMvcUtils.getUserOAuthAccessTokenAuthCode(getMockMvc(), "identity", "identitysecret", user.getId(), user.getUserName(), user.getPassword(), "zones." + identityZone.getId() + ".read");

        MvcResult result = getMockMvc().perform(
            get("/identity-zones/" + identityZone.getId())
                .header("Authorization", "Bearer " + userAccessToken)
                .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())
                .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();

        IdentityZone zoneResult = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<IdentityZone>() {
        });
        assertEquals(identityZone, zoneResult);
        assertNull(zoneResult.getConfig().getSamlConfig().getPrivateKey());
        assertEquals(Collections.EMPTY_MAP, zoneResult.getConfig().getTokenPolicy().getKeys());


        String userAccessTokenReadAndAdmin = mockMvcUtils.getUserOAuthAccessTokenAuthCode(getMockMvc(), "identity", "identitysecret", user.getId(), user.getUserName(), user.getPassword(), "zones." + identityZone.getId() + ".read " + "zones." + identityZone.getId() + ".admin ");

        result = getMockMvc().perform(
            get("/identity-zones/" + identityZone.getId())
                .header("Authorization", "Bearer " + userAccessTokenReadAndAdmin)
                .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())
                .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();

        zoneResult = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<IdentityZone>() {
        });
        assertEquals(identityZone, zoneResult);
        assertNull(zoneResult.getConfig().getSamlConfig().getPrivateKey());
        assertEquals(serviceProviderCertificate, zoneResult.getConfig().getSamlConfig().getCertificate());
        assertNull(zoneResult.getConfig().getSamlConfig().getPrivateKeyPassword());
        assertEquals(Collections.EMPTY_MAP, zoneResult.getConfig().getTokenPolicy().getKeys());
        assertEquals("kid", zoneResult.getConfig().getTokenPolicy().getActiveKeyId());
    }

    @Test
    public void createZoneWithMfaConfigIsNotSupported() throws Exception {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = createGoogleMfaProvider(null);
        String zoneId = new RandomValueStringGenerator(5).generate();
        String zoneContent = "{\"id\" : \""+zoneId+"\", \"name\" : \""+zoneId+"\", \"subdomain\" : \""+zoneId+"\", \"config\" : { \"mfaConfig\" : {\"enabled\" : true, \"providerId\" : \""+mfaProvider.getId()+"\"}}}";
        MockHttpServletResponse response = getMockMvc().perform(post("/identity-zones")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(APPLICATION_JSON)
                .content(zoneContent))
                .andExpect(status().isUnprocessableEntity())
                .andReturn().getResponse();
    }

    @Test
    public void updateZoneWithValidMfaConfig() throws Exception {
        IdentityZone identityZone = createZone(new RandomValueStringGenerator(5).generate(), HttpStatus.CREATED, adminToken, new IdentityZoneConfiguration());
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = createGoogleMfaProvider(identityZone.getId());
        identityZone.getConfig().setMfaConfig(new MfaConfig().setProviderId(mfaProvider.getId()));

        IdentityZone updatedZone = updateZone(identityZone, HttpStatus.OK, adminToken);

        assertEquals(mfaProvider.getId(), updatedZone.getConfig().getMfaConfig().getProviderId());
        assertFalse(updatedZone.getConfig().getMfaConfig().isEnabled());
    }

    @Test
    public void updateZoneWithInvalidMfaConfig() throws Exception {
        IdentityZone identityZone = createZone(new RandomValueStringGenerator(5).generate(), HttpStatus.CREATED, adminToken, new IdentityZoneConfiguration());
        identityZone.getConfig().setMfaConfig(new MfaConfig().setProviderId("INVALID_ID"));

        updateZone(identityZone, HttpStatus.UNPROCESSABLE_ENTITY, adminToken);
    }

    private MfaProvider<GoogleMfaProviderConfig> createGoogleMfaProvider(String zoneId) throws Exception {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = new MfaProvider().setName(new RandomValueStringGenerator(5).generate());
        MockHttpServletRequestBuilder createMfaRequest = post("/mfa-providers")
                .header("Authorization", "Bearer " + adminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(mfaProvider));
        if(hasText(zoneId)){
            createMfaRequest.header("X-Identity-Zone-Id", zoneId);
        }
        MockHttpServletResponse mfaProviderResponse = getMockMvc().perform(createMfaRequest).andReturn().getResponse();
        mfaProvider = JsonUtils.readValue(mfaProviderResponse.getContentAsString(), MfaProvider.class);
        return mfaProvider;
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

    private IdentityZone createZone(String id, HttpStatus expect, String token, IdentityZoneConfiguration zoneConfiguration) throws Exception {
        IdentityZone identityZone = getIdentityZone(id);
        identityZone.setConfig(zoneConfiguration);
        identityZone.getConfig().getSamlConfig().setPrivateKey(serviceProviderKey);
        identityZone.getConfig().getSamlConfig().setPrivateKeyPassword(serviceProviderKeyPassword);
        identityZone.getConfig().getSamlConfig().setCertificate(serviceProviderCertificate);
        Map<String, String> keys = new HashMap<>();
        keys.put("kid", "key");
        identityZone.getConfig().getTokenPolicy().setKeys(keys);
        identityZone.getConfig().getTokenPolicy().setActiveKeyId("kid");

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
            if (hasText(origin) && !origin.contains("opaque-token=present")) {
                assertTrue(origin.contains("iss=" + issuer));
                assertTrue(origin.contains("sub=" + subject));
            }
        }
    }

    private IdentityZone getIdentityZone(String id) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(hasText(id) ? id : new RandomValueStringGenerator().generate());
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
