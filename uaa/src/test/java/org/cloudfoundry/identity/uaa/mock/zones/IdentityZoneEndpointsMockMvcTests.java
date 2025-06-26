package org.cloudfoundry.identity.uaa.mock.zones;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.client.event.ClientCreateEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientDeleteEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientRegistrationService;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
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
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.KeyWithCertTest;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation.Banner;
import org.cloudfoundry.identity.uaa.zone.Consent;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.cloudfoundry.identity.uaa.zone.UserConfig;
import org.cloudfoundry.identity.uaa.zone.ZoneManagementScopes;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneModifiedEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.OPAQUE;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.EMPTY_STRING;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

// TODO: This class has a lot of helpers, why?
@DefaultTestContext
class IdentityZoneEndpointsMockMvcTests {

    private static final String SERVICE_PROVIDER_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIICXQIBAAKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5
            L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vA
            fpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQAB
            AoGAVOj2Yvuigi6wJD99AO2fgF64sYCm/BKkX3dFEw0vxTPIh58kiRP554Xt5ges
            7ZCqL9QpqrChUikO4kJ+nB8Uq2AvaZHbpCEUmbip06IlgdA440o0r0CPo1mgNxGu
            lhiWRN43Lruzfh9qKPhleg2dvyFGQxy5Gk6KW/t8IS4x4r0CQQD/dceBA+Ndj3Xp
            ubHfxqNz4GTOxndc/AXAowPGpge2zpgIc7f50t8OHhG6XhsfJ0wyQEEvodDhZPYX
            kKBnXNHzAkEAyCA76vAwuxqAd3MObhiebniAU3SnPf2u4fdL1EOm92dyFs1JxyyL
            gu/DsjPjx6tRtn4YAalxCzmAMXFSb1qHfwJBAM3qx3z0gGKbUEWtPHcP7BNsrnWK
            vw6By7VC8bk/ffpaP2yYspS66Le9fzbFwoDzMVVUO/dELVZyBnhqSRHoXQcCQQCe
            A2WL8S5o7Vn19rC0GVgu3ZJlUrwiZEVLQdlrticFPXaFrn3Md82ICww3jmURaKHS
            N+l4lnMda79eSp3OMmq9AkA0p79BvYsLshUJJnvbk76pCjR28PK4dV1gSDUEqQMB
            qy45ptdwJLqLJCeNoR0JUcDNIRhOCuOPND7pcMtX6hI/
            -----END RSA PRIVATE KEY-----""";

    private static final String SERVICE_PROVIDER_KEY_PASSWORD = "password";

    private static final String SERVICE_PROVIDER_CERTIFICATE = """
            -----BEGIN CERTIFICATE-----
            MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEO
            MAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEO
            MAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5h
            cnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwx
            CzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAM
            BgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAb
            BgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GN
            ADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39W
            qS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOw
            znoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4Ha
            MIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGc
            gBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYD
            VQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYD
            VQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJh
            QGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ
            0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxC
            KdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkK
            RpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=
            -----END CERTIFICATE-----""";

    private final AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();
    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private TestClient testClient;
    @Autowired
    private ConfigurableApplicationContext configurableApplicationContext;
    @Autowired
    private ClientRegistrationService clientRegistrationService;
    @Autowired
    private ScimGroupProvisioning scimGroupProvisioning;
    @Autowired
    private ScimGroupMembershipManager scimGroupMembershipManager;

    private String identityClientToken;
    private String identityClientZonesReadToken;
    private String identityClientZonesWriteToken;
    private String adminToken;
    private TestApplicationEventListener<IdentityZoneModifiedEvent> zoneModifiedEventListener;
    private TestApplicationEventListener<ClientCreateEvent> clientCreateEventListener;
    private TestApplicationEventListener<ClientDeleteEvent> clientDeleteEventListener;
    private TestApplicationEventListener<GroupModifiedEvent> groupModifiedEventListener;
    private TestApplicationEventListener<UserModifiedEvent> userModifiedEventListener;
    private TestApplicationEventListener<AbstractUaaEvent> uaaEventListener;
    private String lowPrivilegeToken;
    private JdbcIdentityZoneProvisioning provisioning;
    private String uaaAdminClientToken;
    private String uaaAdminUserToken;
    private DbUtils dbUtils;

    @BeforeEach
    void setUp() throws Exception {
        dbUtils = webApplicationContext.getBean(DbUtils.class);

        UaaClientDetails uaaAdminClient = new UaaClientDetails("uaa-admin-" + generator.generate().toLowerCase(),
                null,
                "uaa.admin",
                "password,client_credentials",
                "uaa.admin");
        uaaAdminClient.setClientSecret("secret");
        clientRegistrationService.addClientDetails(uaaAdminClient);

        uaaAdminClientToken = testClient.getClientCredentialsOAuthAccessToken(
                uaaAdminClient.getClientId(),
                "secret",
                "uaa.admin");

        ScimUser uaaAdminUser = createUser(uaaAdminClientToken, null);

        String groupId = scimGroupProvisioning.getByName("uaa.admin", IdentityZone.getUaaZoneId()).getId();
        scimGroupMembershipManager.addMember(groupId, new ScimGroupMember<>(uaaAdminUser.getId()), IdentityZone.getUaaZoneId());

        uaaAdminUserToken = testClient.getUserOAuthAccessToken(
                uaaAdminClient.getClientId(),
                uaaAdminClient.getClientSecret(),
                uaaAdminUser.getUserName(),
                "password",
                "uaa.admin"
        );

        zoneModifiedEventListener = MockMvcUtils.addEventListener(configurableApplicationContext, IdentityZoneModifiedEvent.class);
        clientCreateEventListener = MockMvcUtils.addEventListener(configurableApplicationContext, ClientCreateEvent.class);
        clientDeleteEventListener = MockMvcUtils.addEventListener(configurableApplicationContext, ClientDeleteEvent.class);
        groupModifiedEventListener = MockMvcUtils.addEventListener(configurableApplicationContext, GroupModifiedEvent.class);
        userModifiedEventListener = MockMvcUtils.addEventListener(configurableApplicationContext, UserModifiedEvent.class);
        uaaEventListener = MockMvcUtils.addEventListener(configurableApplicationContext, AbstractUaaEvent.class);
        JdbcTemplate jdbcTemplate = webApplicationContext.getBean(JdbcTemplate.class);
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
        lowPrivilegeToken = testClient.getClientCredentialsOAuthAccessToken(
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

    @AfterEach
    void after() {
        IdentityZoneHolder.clear();
        MockMvcUtils.removeEventListener(webApplicationContext, zoneModifiedEventListener);
        MockMvcUtils.removeEventListener(webApplicationContext, clientCreateEventListener);
        MockMvcUtils.removeEventListener(webApplicationContext, clientDeleteEventListener);
        MockMvcUtils.removeEventListener(webApplicationContext, groupModifiedEventListener);
        MockMvcUtils.removeEventListener(webApplicationContext, userModifiedEventListener);
    }

    @Test
    void create_zone_as_with_uaa_admin_client() throws Exception {
        createZoneUsingToken(uaaAdminClientToken);
    }

    @Test
    void create_zone_as_with_uaa_admin_user() throws Exception {
        createZoneUsingToken(uaaAdminUserToken);
    }

    @Test
    void read_zone_as_with_uaa_admin() throws Exception {
        IdentityZone zone = createZoneUsingToken(uaaAdminClientToken);
        for (String token : Arrays.asList(uaaAdminClientToken, uaaAdminUserToken)) {
            mockMvc.perform(
                            get("/identity-zones")
                                    .header("Authorization", "Bearer " + token)
                                    .header("Accept", MediaType.APPLICATION_JSON_VALUE)
                    )
                    .andExpect(status().isOk());
            mockMvc.perform(
                            get("/identity-zones/{id}", zone.getId())
                                    .header("Authorization", "Bearer " + token)
                                    .header("Accept", MediaType.APPLICATION_JSON_VALUE)
                    )
                    .andExpect(status().isOk());
        }
    }

    @Test
    void update_zone_as_with_uaa_admin() throws Exception {
        IdentityZone zone = createZoneUsingToken(uaaAdminClientToken);
        for (String token : Arrays.asList(uaaAdminClientToken, uaaAdminUserToken)) {
            updateZone(zone, HttpStatus.OK, token);
        }
    }

    @Test
    void create_zone_using_no_token() throws Exception {
        createZone(generator.generate().toLowerCase(),
                HttpStatus.UNAUTHORIZED,
                "",
                new IdentityZoneConfiguration());
    }

    @Test
    void delete_zone_as_with_uaa_admin() throws Exception {
        for (String token : Arrays.asList(uaaAdminClientToken, uaaAdminUserToken)) {
            IdentityZone zone = createZoneUsingToken(token);
            mockMvc.perform(
                            delete("/identity-zones/{id}", zone.getId())
                                    .header("Authorization", "Bearer " + token)
                                    .accept(APPLICATION_JSON))
                    .andExpect(status().isOk());
        }
    }

    @ParameterizedTest
    @MethodSource("parameters")
    void readWithoutTokenShouldFail(String url) throws Exception {
        mockMvc.perform(get(url))
                .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @MethodSource("parameters")
    void readWith_Write_TokenShouldNotFail(String url) throws Exception {
        mockMvc.perform(
                        get(url)
                                .header("Authorization", "Bearer " + identityClientZonesWriteToken))
                .andExpect(status().isOk());
    }

    @ParameterizedTest
    @MethodSource("parameters")
    void readWith_Read_TokenShouldSucceed(String url) throws Exception {
        mockMvc.perform(
                        get(url)
                                .header("Authorization", "Bearer " + identityClientZonesReadToken))
                .andExpect(status().isOk());
    }

    @Test
    void create_zone_no_links() throws Exception {
        String id = generator.generate().toLowerCase();
        IdentityZoneConfiguration zoneConfiguration = new IdentityZoneConfiguration();
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, zoneConfiguration);
        assertThat(created.getConfig().getLinks().getHomeRedirect()).isNull();
        assertThat(created.getConfig().getLinks().getSelfService().getSignup()).isNull();
        assertThat(created.getConfig().getLinks().getSelfService().getPasswd()).isNull();
        IdentityZone retrieved = getIdentityZone(id, HttpStatus.OK, identityClientToken);
        assertThat(retrieved.getConfig().getLinks().getHomeRedirect()).isNull();
        assertThat(retrieved.getConfig().getLinks().getSelfService().getSignup()).isNull();
        assertThat(retrieved.getConfig().getLinks().getSelfService().getPasswd()).isNull();
    }

    @Test
    void create_and_update_with_links() throws Exception {
        String id = generator.generate().toLowerCase();
        IdentityZoneConfiguration zoneConfiguration = new IdentityZoneConfiguration();
        zoneConfiguration.getLinks().setHomeRedirect("/home");
        zoneConfiguration.getLinks().getSelfService().setSignup("/signup");
        zoneConfiguration.getLinks().getSelfService().setPasswd("/passwd");
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, zoneConfiguration);
        assertThat(created.getConfig().getLinks().getHomeRedirect()).isEqualTo("/home");
        assertThat(created.getConfig().getLinks().getSelfService().getSignup()).isEqualTo("/signup");
        assertThat(created.getConfig().getLinks().getSelfService().getPasswd()).isEqualTo("/passwd");
        IdentityZone retrieved = getIdentityZone(id, HttpStatus.OK, identityClientToken);
        assertThat(retrieved.getConfig().getLinks().getHomeRedirect()).isEqualTo("/home");
        assertThat(retrieved.getConfig().getLinks().getSelfService().getSignup()).isEqualTo("/signup");
        assertThat(retrieved.getConfig().getLinks().getSelfService().getPasswd()).isEqualTo("/passwd");

        zoneConfiguration = created.getConfig();
        zoneConfiguration.getLinks().setHomeRedirect(null);
        zoneConfiguration.getLinks().getSelfService().setSignup(null);
        zoneConfiguration.getLinks().getSelfService().setPasswd(null);
        IdentityZone updated = updateZone(created, HttpStatus.OK, identityClientToken);
        assertThat(updated.getConfig().getLinks().getHomeRedirect()).isNull();
        assertThat(updated.getConfig().getLinks().getSelfService().getSignup()).isNull();
        assertThat(updated.getConfig().getLinks().getSelfService().getPasswd()).isNull();
    }

    @Test
    void getZoneAsIdentityClient() throws Exception {
        String id = generator.generate();
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        IdentityZone retrieved = getIdentityZone(id, HttpStatus.OK, identityClientToken);
        assertThat(retrieved.getId()).isEqualTo(created.getId());
        assertThat(retrieved.getName()).isEqualTo(created.getName());
        assertThat(retrieved.getSubdomain()).isEqualTo(created.getSubdomain());
        assertThat(retrieved.getDescription()).isEqualTo(created.getDescription());
    }

    @Test
    void bootstrapped_system_scopes() throws Exception {
        String id = generator.generate();
        createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        List<String> groups = webApplicationContext.getBean(JdbcScimGroupProvisioning.class)
                .retrieveAll(id).stream().map(ScimGroup::getDisplayName).toList();

        assertThat(groups).as("Scopes should have been bootstrapped into the new zone").containsAll(ZoneManagementScopes.getSystemScopes());
    }

    @Test
    void getZonesAsIdentityClient() throws Exception {
        String id = generator.generate();
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        mockMvc.perform(
                        get("/identity-zones/")
                                .header("Authorization", "Bearer " + lowPrivilegeToken))
                .andExpect(status().isForbidden());

        MvcResult result = mockMvc.perform(
                        get("/identity-zones/")
                                .header("Authorization", "Bearer " + identityClientToken))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();

        List<IdentityZone> zones = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<>() {
        });
        IdentityZone retrieved = null;
        for (IdentityZone identityZone : zones) {
            if (identityZone.getId().equals(id)) {
                retrieved = identityZone;
            }
        }

        assertThat(retrieved)
                .returns(created.getId(), IdentityZone::getId)
                .returns(created.getName(), IdentityZone::getName)
                .returns(created.getSubdomain(), IdentityZone::getSubdomain)
                .returns(created.getDescription(), IdentityZone::getDescription);
    }

    @Test
    void getZoneThatDoesntExist() throws Exception {
        String id = generator.generate();
        getIdentityZone(id, HttpStatus.NOT_FOUND, identityClientToken);
    }

    @Test
    void createZone() throws Exception {
        createZoneReturn();
    }

    @Test
    void updateZoneCreatesGroups() throws Exception {
        IdentityZone zone = createZoneReturn();
        List<String> zoneGroups = new LinkedList<>(zone.getConfig().getUserConfig().getDefaultGroups());

        //test two times with the same groups
        zone = updateZone(zone, HttpStatus.OK, identityClientToken);

        zoneGroups.add("updated.group.1");
        zoneGroups.add("updated.group.2");
        zone.getConfig().getUserConfig().setDefaultGroups(zoneGroups);
        zone = updateZone(zone, HttpStatus.OK, identityClientToken);

        //validate that default groups got created
        ScimGroupProvisioning groupProvisioning = webApplicationContext.getBean(ScimGroupProvisioning.class);
        for (String g : zoneGroups) {
            assertThat(groupProvisioning.getByName(g, zone.getId())).isNotNull();
        }
    }

    @Test
    void createZoneWithNoNameFailsWithUnprocessableEntity() throws Exception {
        String id = generator.generate();
        IdentityZone zone = this.createSimpleIdentityZone(id);
        zone.setName(null);

        mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("invalid_identity_zone"))
                .andExpect(jsonPath("$.error_description").value("The identity zone must be given a name."));

        assertThat(zoneModifiedEventListener.getEventCount()).isZero();
    }

    @Test
    void createZoneWithNoSubdomainFailsWithUnprocessableEntity() throws Exception {
        String id = generator.generate();
        IdentityZone zone = this.createSimpleIdentityZone(id);
        zone.setSubdomain(null);

        mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("invalid_identity_zone"))
                .andExpect(jsonPath("$.error_description").value("The subdomain must be provided."));

        assertThat(zoneModifiedEventListener.getEventCount()).isZero();
    }

    @Test
    void createZoneWithNoAllowedGroupsFailsWithUnprocessableEntity() throws Exception {
        String id = generator.generate();
        IdentityZone zone = this.createSimpleIdentityZone(id);
        zone.getConfig().getUserConfig().setDefaultGroups(Collections.emptyList());
        zone.getConfig().getUserConfig().setAllowedGroups(Collections.emptyList()); // no groups allowed

        mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("invalid_identity_zone"))
                .andExpect(jsonPath("$.error_description").value("The identity zone details are invalid. " +
                        "The zone configuration is invalid. At least one group must be allowed"));

        assertThat(zoneModifiedEventListener.getEventCount()).isZero();
    }

    @Test
    void createZone_ShouldOnlyCreateGroupsForSystemScopesThatAreInAllowList() throws Exception {
        final String idzId = generator.generate();

        final IdentityZone idz = createSimpleIdentityZone(idzId);
        idz.getConfig().getUserConfig().setAllowedGroups(List.of("scim.write", "scim.read"));
        idz.getConfig().getUserConfig().setDefaultGroups(Collections.emptyList());

        // create the zone
        mockMvc.perform(
                post("/identity-zones")
                        .header("Authorization", "Bearer " + identityClientToken)
                        .contentType(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(idz))
        ).andExpect(status().isCreated());

        final String zoneAdminUserToken = createZoneAdminAndGetToken(idzId);

        final SearchResults<ScimGroup> groupsResult = MockMvcUtils.getGroups(mockMvc, zoneAdminUserToken, idzId);
        assertThat(groupsResult).isNotNull();
        assertThat(groupsResult.getTotalResults()).isEqualTo(2);

        final Set<String> groupNamesInZone = groupsResult.getResources().stream()
                .map(ScimGroup::getDisplayName)
                .collect(Collectors.toSet());
        assertThat(groupNamesInZone)
                .containsExactlyInAnyOrder("scim.read", "scim.write");
    }

    private String createZoneAdminAndGetToken(final String idzId) throws Exception {
        final String myAdminToken = MockMvcUtils.getClientOAuthAccessToken(
                mockMvc,
                "admin",
                "adminsecret",
                EMPTY_STRING
        );

        final String zoneAdminScope = "zones.%s.admin".formatted(idzId);
        final ScimUser zoneAdminUser = MockMvcUtils.createAdminForZone(
                mockMvc,
                myAdminToken,
                zoneAdminScope,
                IdentityZone.getUaaZoneId()
        );

        return MockMvcUtils.getUserOAuthAccessToken(
                mockMvc,
                "identity",
                "identitysecret",
                zoneAdminUser.getUserName(),
                "secr3T",
                zoneAdminScope,
                IdentityZone.getUaa()
        );
    }

    @Test
    void createZoneInsufficientScope() throws Exception {
        String id = new AlphanumericRandomValueStringGenerator().generate();
        createZone(id, HttpStatus.FORBIDDEN, lowPrivilegeToken, new IdentityZoneConfiguration());

        assertThat(zoneModifiedEventListener.getEventCount()).isZero();
    }

    @Test
    void createZoneNoToken() throws Exception {
        String id = new AlphanumericRandomValueStringGenerator().generate();
        createZone(id, HttpStatus.UNAUTHORIZED, "", new IdentityZoneConfiguration());

        assertThat(zoneModifiedEventListener.getEventCount()).isZero();
    }

    @Test
    void createZoneWithoutID() throws Exception {
        IdentityZone zone = createZone("", HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        assertThat(hasText(zone.getId())).isTrue();
        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);
    }

    @Test
    void updateNonExistentReturns403() throws Exception {
        String id = new AlphanumericRandomValueStringGenerator().generate();
        IdentityZone identityZone = createSimpleIdentityZone(id);
        //zone doesn't exist and we don't have the token scope
        updateZone(identityZone, HttpStatus.FORBIDDEN, lowPrivilegeToken);

        assertThat(zoneModifiedEventListener.getEventCount()).isZero();
    }

    @Test
    void updateUaaIsForbidden() throws Exception {
        updateZone(IdentityZone.getUaa(), HttpStatus.FORBIDDEN, identityClientToken);
        assertThat(zoneModifiedEventListener.getEventCount()).isZero();
    }

    @Test
    void updateNonExistentReturns404() throws Exception {
        String id = generator.generate();
        IdentityZone identityZone = createSimpleIdentityZone(id);
        updateZone(identityZone, HttpStatus.NOT_FOUND, identityClientToken);

        assertThat(zoneModifiedEventListener.getEventCount()).isZero();
    }

    @Test
    void updateWithSameDataReturns200() throws Exception {
        String id = generator.generate();
        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        updateZone(created, HttpStatus.OK, identityClientToken);
        checkZoneAuditEventInUaa(2, AuditEventType.IdentityZoneModifiedEvent);
    }

    @Test
    void updateWithDifferentDataReturns200() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);
        created.setDescription("updated description");
        IdentityZoneConfiguration definition = new IdentityZoneConfiguration(new TokenPolicy(3600, 7200));
        created.setConfig(definition);

        IdentityZone updated = updateZone(created, HttpStatus.OK, identityClientToken);
        assertThat(updated.getDescription()).isEqualTo("updated description");
        assertThat(JsonUtils.writeValueAsString(updated.getConfig())).isEqualTo(JsonUtils.writeValueAsString(definition));
        checkZoneAuditEventInUaa(2, AuditEventType.IdentityZoneModifiedEvent);
    }

    @Test
    void createAndUpdateDoesNotReturnKeys() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        assertThat(created.getConfig().getTokenPolicy().getKeys()).isEqualTo(emptyMap());
        assertThat(created.getConfig().getTokenPolicy().getActiveKeyId()).isEqualTo("kid");
        assertThat(created.getConfig().getSamlConfig().getPrivateKey()).isNull();
        assertThat(created.getConfig().getSamlConfig().getPrivateKeyPassword()).isNull();
        assertThat(created.getConfig().getSamlConfig().getCertificate()).isNotNull();
        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);
        created.setDescription("updated description");
        TokenPolicy tokenPolicy = new TokenPolicy(3600, 7200);
        HashMap<String, String> keys = new HashMap<>();
        keys.put("key1", "value1");
        tokenPolicy.setKeys(keys);
        tokenPolicy.setActiveKeyId("key1");
        SamlConfig samlConfig = new SamlConfig();
        samlConfig.setCertificate(SERVICE_PROVIDER_CERTIFICATE);
        samlConfig.setPrivateKey(SERVICE_PROVIDER_KEY);
        samlConfig.setPrivateKeyPassword(SERVICE_PROVIDER_KEY_PASSWORD);
        IdentityZoneConfiguration definition = new IdentityZoneConfiguration(tokenPolicy);
        definition.setSamlConfig(samlConfig);
        created.setConfig(definition);

        IdentityZone updated = updateZone(created, HttpStatus.OK, identityClientToken);
        assertThat(updated.getDescription()).isEqualTo("updated description");
        assertThat(updated.getConfig().getTokenPolicy().getKeys()).isEqualTo(emptyMap());
        assertThat(updated.getConfig().getTokenPolicy().getActiveKeyId()).isEqualTo("key1");
        assertThat(updated.getConfig().getSamlConfig().getPrivateKey()).isNull();
        assertThat(updated.getConfig().getSamlConfig().getPrivateKeyPassword()).isNull();
        assertThat(updated.getConfig().getSamlConfig().getCertificate()).isEqualTo(SERVICE_PROVIDER_CERTIFICATE);
    }

    @Test
    void updateIgnoresKeysWhenNotPresentInPayload() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        IdentityZone retrieve = provisioning.retrieve(created.getId());

        Map<String, String> keys = new HashMap<>();
        keys.put("kid", "key");

        assertThat(retrieve.getConfig().getTokenPolicy().getKeys().get("kid").getSigningKey()).isEqualTo(keys.get("kid"));

        created.setDescription("updated description");
        created.getConfig().getTokenPolicy().setKeys(null);
        updateZone(created, HttpStatus.OK, identityClientToken);
        retrieve = provisioning.retrieve(created.getId());
        String keyId = retrieve.getConfig().getTokenPolicy().getActiveKeyId();
        assertThat(retrieve.getConfig().getTokenPolicy().getKeys().get(keyId).getSigningKey()).isEqualTo(keys.get(keyId));
    }

    @Test
    void updateWithInvalidSamlKeyCertPair() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        String samlPrivateKey = """
                -----BEGIN RSA PRIVATE KEY-----
                Proc-Type: 4,ENCRYPTED
                DEK-Info: DES-EDE3-CBC,5771044F3450A262
                
                VfRgIdzq/TUFdIwTOxochDs02sSQXA/Z6mRnffYTQMwXpQ5f5nRuqcY8zECGMaDe
                aLrndpWzGbxiePKgN5AxuIDYNnKMrDRgyCzaaPx66rb87oMwtuq1HM18qqs+yN5v
                CdsoS2uz57fCDI24BuJkIDSIeumLXc5MdN0HUeaxOVzmpbpsbBXjRYa24gW38mUh
                DzmOAsNDxfoSTox02Cj+GV024e+PiWR6AMA7RKhsKPf9F4ctWwozvEHrV8fzTy5B
                +KM361P7XwJYueiV/gMZW2DXSujNRBEVfC1CLaxDV3eVsFX5iIiUbc4JQYOM6oQ3
                KxGPImcRQPY0asKgEDIaWtysUuBoDSbfQ/FxGWeqwR6P/Vth4dXzVGheYLu1V1CU
                o6M+EXC/VUhERKwi13EgqXLKrDI352/HgEKG60EhM6xIJy9hLHy0UGjdHDcA+cF6
                NEl6E3CivddMHIPQWil5x4AMaevGa3v/gcZI0DN8t7L1g4fgjtSPYzvwmOxoxHGi
                7V7PdzaD4GWV75fv99sBlq2e0KK9crNUzs7vbFA/m6tgNA628SGhU1uAc/5xOskI
                0Ez6kjgHoh4U7t/fu7ey1MbFQt6byHY9lk27nW1ub/QMAaRJ+EDnrReB/NN6q5Vu
                h9eQNniNOeQfflzFyPB9omLNsVJkENn+lZNNrrlbn8OmJ0pT58Iaetfh79rDZPw9
                zmHVqmMynmecTWAcA9ATf7+lh+xV88JDjQkLcG/3WEXNH7HXKO00pUa8+JtyxbAb
                dAwGgrjJkbbk1qLLScOqY4mA5WXa5+80LMkCYO44vVTp2VKmnxj8Mw==
                -----END RSA PRIVATE KEY-----""";

        String samlKeyPassphrase = "password";

        String samlCertificate = """
                -----BEGIN CERTIFICATE-----
                MIIEbzCCA1egAwIBAgIQCTPRC15ZcpIxJwdwiMVDSjANBgkqhkiG9w0BAQUFADA2
                MQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg
                U1NMIENBMB4XDTEzMDczMDAwMDAwMFoXDTE2MDcyOTIzNTk1OVowPzEhMB8GA1UE
                CxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRowGAYDVQQDExFlZHVyb2FtLmJi
                ay5hYy51azCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANrSBWTl56O2
                VJbahURgPznums43Nnn/smJ6cGywPu4mtJHUHSmONlBDTAWFS1fLkh8YHIQmdwYg
                FY4pHjZmKVtJ6ZOFhDNN1R2VMka4ZtREWn3XX8pUacol5KjEIh6U/FvMHyRv7sV5
                9J6JUK+n5R7ZsSu7XRi6TrT3xhfu0KoWo8RM/salKo2theIcyqLPHiFLEtA7ISLV
                q7I49uj9h9Hni/iCpBey+Gn5yDub4nrv81aDfD6zDoW/vXIOrcXFYRK3lXWOOFi4
                cfmu4SQQwMV1jBOer8JgfsQ3EQMgwauSMLUR31wPM83eMbOC72HhW9SJUtFDj42c
                PIEWd+rTA8ECAwEAAaOCAW4wggFqMB8GA1UdIwQYMBaAFAy9k2gM896ro0lrKzdX
                R+qQ47ntMB0GA1UdDgQWBBQgoU+Pbgk2MthczZt7TviUiIWyrjAOBgNVHQ8BAf8E
                BAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH
                AwIwIgYDVR0gBBswGTANBgsrBgEEAbIxAQICHTAIBgZngQwBAgEwOgYDVR0fBDMw
                MTAvoC2gK4YpaHR0cDovL2NybC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5j
                cmwwbQYIKwYBBQUHAQEEYTBfMDUGCCsGAQUFBzAChilodHRwOi8vY3J0LnRjcy50
                ZXJlbmEub3JnL1RFUkVOQVNTTENBLmNydDAmBggrBgEFBQcwAYYaaHR0cDovL29j
                c3AudGNzLnRlcmVuYS5vcmcwHAYDVR0RBBUwE4IRZWR1cm9hbS5iYmsuYWMudWsw
                DQYJKoZIhvcNAQEFBQADggEBAHTw5b1lrTBqnx/QSO50Mww+OPYgV4b4NSu2rqxG
                I2hHLiD4l7Sk3WOdXPAQMmTlo6N10Lt6p8gLLxKsOAw+nK+z9aLcgKk9/kYoe4C8
                jHzwTy6eO+sCKnJfTqEX8p3b8l736lUWwPgMjjEN+d49ZegqCwH6SEz7h0+DwGmF
                LLfFM8J1SozgPVXgmfCv0XHpFyYQPhXligeWk39FouC2DfhXDTDOgc0n/UQjETNl
                r2Jawuw1VG6/+EFf4qjwr0/hIrxc/0XEd9+qLHKef1rMjb9pcZA7Dti+DoKHsxWi
                yl3DnNZlj0tFP0SBcwjg/66VAekmFtJxsLx3hKxtYpO3m8c=
                -----END CERTIFICATE-----""";

        SamlConfig samlConfig = created.getConfig().getSamlConfig();
        samlConfig.setPrivateKey(samlPrivateKey);
        samlConfig.setPrivateKeyPassword(samlKeyPassphrase);
        samlConfig.setCertificate(samlCertificate);
        updateZone(created, HttpStatus.UNPROCESSABLE_ENTITY, identityClientToken);
    }

    @Test
    void updateWithPartialSamlKeyCertPair() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        SamlConfig samlConfig = created.getConfig().getSamlConfig();
        samlConfig.setPrivateKey(SERVICE_PROVIDER_KEY);
        samlConfig.setPrivateKeyPassword(null);
        samlConfig.setCertificate(SERVICE_PROVIDER_CERTIFICATE);
        updateZone(created, HttpStatus.OK, identityClientToken);

        samlConfig = created.getConfig().getSamlConfig();
        samlConfig.setPrivateKey(null);
        samlConfig.setPrivateKeyPassword(SERVICE_PROVIDER_KEY_PASSWORD);
        samlConfig.setCertificate(SERVICE_PROVIDER_CERTIFICATE);
        updateZone(created, HttpStatus.UNPROCESSABLE_ENTITY, identityClientToken);
    }

    @Test
    void updateWithEmptySamlKeyCertPairRetainsCurrentValue() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        created.getConfig().getTokenPolicy().setKeys(new HashMap<>(Collections.singletonMap("kid", "key")));

        SamlConfig samlConfig = created.getConfig().getSamlConfig();

        samlConfig.setPrivateKey(null);
        samlConfig.setPrivateKeyPassword(null);
        updateZone(created, HttpStatus.OK, identityClientToken);

        IdentityZone updated = provisioning.retrieve(created.getId());
        SamlConfig updatedSamlConfig = updated.getConfig().getSamlConfig();
        assertThat(updatedSamlConfig.getCertificate()).isEqualTo(SERVICE_PROVIDER_CERTIFICATE);
        assertThat(updatedSamlConfig.getPrivateKey()).isEqualTo(SERVICE_PROVIDER_KEY);
        assertThat(updatedSamlConfig.getPrivateKeyPassword()).isEqualTo(SERVICE_PROVIDER_KEY_PASSWORD);
    }

    @Test
    void updateWithNewSamlCertNoKeyIsUnprocessableEntity() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        SamlConfig samlConfig = created.getConfig().getSamlConfig();

        samlConfig.setCertificate(KeyWithCertTest.INVALID_CERT);
        samlConfig.setPrivateKey(null);
        samlConfig.setPrivateKeyPassword(null);
        updateZone(created, HttpStatus.UNPROCESSABLE_ENTITY, identityClientToken);
    }

    @Test
    void updateWithNewKeyNoCertIsUnprocessableEntity() throws Exception {
        String id = generator.generate();

        IdentityZone created = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        SamlConfig samlConfig = created.getConfig().getSamlConfig();

        samlConfig.setCertificate(null);
        samlConfig.setPrivateKey(SERVICE_PROVIDER_KEY);
        samlConfig.setPrivateKeyPassword(SERVICE_PROVIDER_KEY_PASSWORD);
        updateZone(created, HttpStatus.UNPROCESSABLE_ENTITY, identityClientToken);
    }

    @Test
    void updateZoneWithExistingSubdomain() throws Exception {
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
    void updateZoneNoToken() throws Exception {
        String id = new AlphanumericRandomValueStringGenerator().generate();
        IdentityZone identityZone = createSimpleIdentityZone(id);
        updateZone(identityZone, HttpStatus.UNAUTHORIZED, "");

        assertThat(zoneModifiedEventListener.getEventCount()).isZero();
    }

    @Test
    void createDuplicateZoneReturns409() throws Exception {
        String id = generator.generate();
        createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        createZone(id, HttpStatus.CONFLICT, identityClientToken, new IdentityZoneConfiguration());

        assertThat(zoneModifiedEventListener.getEventCount()).isOne();
    }

    public static Stream<String> parameters() {
        return Stream.of("/identity-zones", "/identity-zones/");
    }

    @ParameterizedTest
    @MethodSource("parameters")
    void createZoneAndIdentityProvider(String url) throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = createSimpleIdentityZone(id);
        TokenPolicy tokenPolicy = new TokenPolicy(3600, 7200);
        Map<String, String> jwtKeys = new HashMap<>();
        jwtKeys.put("key_id_1", "secret_key_1");
        jwtKeys.put("key_id_2", "secret_key_2");
        tokenPolicy.setKeys(jwtKeys);
        tokenPolicy.setActiveKeyId("key_id_1");

        SamlConfig samlConfig = new SamlConfig();

        String samlPrivateKey = """
                -----BEGIN RSA PRIVATE KEY-----
                MIICXAIBAAKBgQCpnqPQiDCfJY1hVaQUZG6Rs1Wd3FmP1EStN71hXeXOLog5nvpa
                H45P3v79EGpaO06vH5qSu/xr6kQRBOA4h9OqXGS72BGQBH8jMNCoHqgJrIADQTHX
                H85RYF38bH6Ycp18jch0KVmYwKeiaLNfMDngnAv6wMDONJz761GBtrG1/wIDAQAB
                AoGAPjYeNSzOUICwcyO7E3Omji/tVgHso3EiYznPbvfGgrHUavXhMs7iHm9WrLCp
                oUChYl/ADNOACICayHc2WeWPfxJ26BF0ahTzOX1fJsg++JDweCYCNN2WrrYcyA9o
                XDU18IFh2dY2CvPL8G7ex5WEq9nYTASQzRfC899nTvUSTyECQQDZddRhqF9g6Zc9
                vuSjwQf+dMztsvhLVPAPaSdgE4LMa4nE2iNC/sLq1uUEwrrrOKGaFB9IXeIU7hPW
                2QmgJewxAkEAx65IjpesMEq+zE5qRPYkfxjdaa0gNBCfATEBGI4bTx37cKskf49W
                2qFlombE9m9t/beYXVC++2W40i53ov+pLwJALRp0X4EFr1sjxGnIkHJkDxH4w0CA
                oVdPp1KfGR1S3sVbQNohwC6JDR5fR/p/vHP1iLituFvInaC3urMvfOkAsQJBAJg9
                0gYdr+O16Vi95JoljNf2bkG3BJmNnp167ln5ZurgcieJ5K7464CPk3zJnBxEAvlx
                dFKZULM98DcXxJFbGXMCQC2ZkPFgzMlRwYu4gake2ruOQR9N3HzLoau1jqDrgh6U
                Ow3ylw8RWPq4zmLkDPn83DFMBquYsg3yzBPi7PANBO4=
                -----END RSA PRIVATE KEY-----""";

        String samlKeyPassphrase = "password";

        String samlCertificate = """
                -----BEGIN CERTIFICATE-----
                MIID4zCCA0ygAwIBAgIJAJdmwmBdhEydMA0GCSqGSIb3DQEBBQUAMIGoMQswCQYD
                VQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xJzAl
                BgNVBAoTHkNsb3VkIEZvdW5kcnkgRm91bmRhdGlvbiwgSW5jLjEMMAoGA1UECxMD
                VUFBMRIwEAYDVQQDEwlsb2NhbGhvc3QxKTAnBgkqhkiG9w0BCQEWGmNmLWlkZW50
                aXR5LWVuZ0BwaXZvdGFsLmlvMB4XDTE2MDIxNjIyMTMzN1oXDTE2MDMxNzIyMTMz
                N1owgagxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZy
                YW5jaXNjbzEnMCUGA1UEChMeQ2xvdWQgRm91bmRyeSBGb3VuZGF0aW9uLCBJbmMu
                MQwwCgYDVQQLEwNVQUExEjAQBgNVBAMTCWxvY2FsaG9zdDEpMCcGCSqGSIb3DQEJ
                ARYaY2YtaWRlbnRpdHktZW5nQHBpdm90YWwuaW8wgZ8wDQYJKoZIhvcNAQEBBQAD
                gY0AMIGJAoGBAKmeo9CIMJ8ljWFVpBRkbpGzVZ3cWY/URK03vWFd5c4uiDme+lof
                jk/e/v0Qalo7Tq8fmpK7/GvqRBEE4DiH06pcZLvYEZAEfyMw0KgeqAmsgANBMdcf
                zlFgXfxsfphynXyNyHQpWZjAp6Jos18wOeCcC/rAwM40nPvrUYG2sbX/AgMBAAGj
                ggERMIIBDTAdBgNVHQ4EFgQUdiixDfiZ61ljk7J/uUYcay26n5swgd0GA1UdIwSB
                1TCB0oAUdiixDfiZ61ljk7J/uUYcay26n5uhga6kgaswgagxCzAJBgNVBAYTAlVT
                MQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEnMCUGA1UEChMe
                Q2xvdWQgRm91bmRyeSBGb3VuZGF0aW9uLCBJbmMuMQwwCgYDVQQLEwNVQUExEjAQ
                BgNVBAMTCWxvY2FsaG9zdDEpMCcGCSqGSIb3DQEJARYaY2YtaWRlbnRpdHktZW5n
                QHBpdm90YWwuaW+CCQCXZsJgXYRMnTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB
                BQUAA4GBAAPf/SPl/LuVYrl0HDUU8YDR3N7Fi4OjhF3+n+uBYRhO+9IbQ/t1sC1p
                enWhiAfyZtgFv2OmjvtFyty9YqHhIPAg9Ceod37Q7HNSG04vbYHNJ6XhGUzacMj8
                hQ1ZzQBv+CaKWZarBIql/TsxtpvvXhaE4QqR4NvUDnESHtxefriv
                -----END CERTIFICATE-----""";

        samlConfig.setCertificate(samlCertificate);
        samlConfig.setPrivateKey(samlPrivateKey);
        samlConfig.setPrivateKeyPassword(samlKeyPassphrase);

        IdentityZoneConfiguration definition = new IdentityZoneConfiguration(tokenPolicy);
        identityZone.setConfig(definition.setSamlConfig(samlConfig));

        mockMvc.perform(
                        post(url)
                                .header("Authorization", "Bearer " + identityClientZonesReadToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isForbidden());

        mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isCreated());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        IdentityProviderProvisioning idpp = (IdentityProviderProvisioning) webApplicationContext.getBean("identityProviderProvisioning");
        IdentityProvider<?> idp1 = idpp.retrieveByOrigin(UAA, identityZone.getId());
        IdentityProvider<?> idp2 = idpp.retrieveByOrigin(UAA, IdentityZone.getUaaZoneId());
        assertThat(idp2).isNotEqualTo(idp1);

        IdentityZoneProvisioning identityZoneProvisioning = webApplicationContext.getBean(IdentityZoneProvisioning.class);
        IdentityZone createdZone = identityZoneProvisioning.retrieve(id);

        assertThat(JsonUtils.writeValueAsString(createdZone.getConfig())).isEqualTo(JsonUtils.writeValueAsString(definition));
        assertThat(createdZone.getConfig().getSamlConfig().getCertificate()).isEqualTo(samlCertificate);
        assertThat(createdZone.getConfig().getSamlConfig().getPrivateKey()).isEqualTo(samlPrivateKey);
    }

    @Test
    void createZoneWithInvalidPrimarySigningKeyId() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = createSimpleIdentityZone(id);
        TokenPolicy tokenPolicy = identityZone.getConfig().getTokenPolicy();
        Map<String, String> jwtKeys = new HashMap<>();
        jwtKeys.put("key_id_1", "secret_key_1");
        jwtKeys.put("key_id_2", "secret_key_2");
        tokenPolicy.setKeys(jwtKeys);
        tokenPolicy.setActiveKeyId("nonexistent_key");

        mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isUnprocessableEntity());
    }

    @Test
    void createZoneWithNoActiveKeyId() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = createSimpleIdentityZone(id);
        TokenPolicy tokenPolicy = identityZone.getConfig().getTokenPolicy();
        Map<String, String> jwtKeys = new HashMap<>();
        jwtKeys.put("key_id_1", "secret_key_1");
        jwtKeys.put("key_id_2", "secret_key_2");
        jwtKeys.put("key_id_3", "secret_key_3");
        tokenPolicy.setKeys(jwtKeys);

        mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isCreated());
    }

    @Test
    void createZoneWithRefreshTokenConfig() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = createSimpleIdentityZone(id);
        TokenPolicy tokenPolicy = identityZone.getConfig().getTokenPolicy();
        tokenPolicy.setRefreshTokenFormat(OPAQUE.getStringValue().toUpperCase());
        tokenPolicy.setRefreshTokenUnique(true);
        tokenPolicy.setRefreshTokenRotate(true);

        mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.config.tokenPolicy.refreshTokenUnique").value(true))
                .andExpect(jsonPath("$.config.tokenPolicy.refreshTokenRotate").value(true))
                .andExpect(jsonPath("$.config.tokenPolicy.refreshTokenFormat").value(OPAQUE.getStringValue()));

        IdentityZone createdZone = provisioning.retrieve(id);
        assertThat(createdZone.getConfig().getTokenPolicy().getRefreshTokenFormat()).isEqualTo(OPAQUE.getStringValue());
        assertThat(createdZone.getConfig().getTokenPolicy().isRefreshTokenUnique()).isTrue();
        assertThat(createdZone.getConfig().getTokenPolicy().isRefreshTokenRotate()).isTrue();
    }

    @Test
    void createZoneWithCustomBrandingBanner() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);
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

        String contentAsString = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andReturn().getResponse().getContentAsString();
        IdentityZone createdZone = JsonUtils.readValue(contentAsString, IdentityZone.class);

        Banner zoneBanner = createdZone.getConfig().getBranding().getBanner();
        assertThat(zoneBanner)
                .returns(text, Banner::getText)
                .returns(link, Banner::getLink)
                .returns(backgroundColor, Banner::getBackgroundColor);
    }

    @Test
    void createZoneWithConsentTextAndLink() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);

        BrandingInformation branding = new BrandingInformation();
        Consent consent = new Consent("some consent text", "http://localhost");
        branding.setConsent(consent);
        zone.getConfig().setBranding(branding);

        String contentAsString = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andReturn().getResponse().getContentAsString();
        IdentityZone createdZone = JsonUtils.readValue(contentAsString, IdentityZone.class);

        Consent createdZoneConsent = createdZone.getConfig().getBranding().getConsent();
        assertThat(createdZoneConsent)
                .returns("some consent text", Consent::getText)
                .returns("http://localhost", Consent::getLink);
    }

    @Test
    void createZoneWithOnlyConsentText() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);

        BrandingInformation branding = new BrandingInformation();
        Consent consent = new Consent("some consent text", null);
        branding.setConsent(consent);
        zone.getConfig().setBranding(branding);

        String contentAsString = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andReturn().getResponse().getContentAsString();
        IdentityZone createdZone = JsonUtils.readValue(contentAsString, IdentityZone.class);

        Consent createdZoneConsent = createdZone.getConfig().getBranding().getConsent();
        assertThat(createdZoneConsent)
                .returns("some consent text", Consent::getText)
                .returns(null, Consent::getLink);
    }

    @Test
    void createZoneWithNoConsentText() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);

        BrandingInformation branding = new BrandingInformation();
        Consent consent = new Consent(null, "http://localhost");
        branding.setConsent(consent);
        zone.getConfig().setBranding(branding);

        String contentAsString = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn().getResponse().getContentAsString();

        assertThat(contentAsString).contains("Consent text must be set if configuring consent");
    }

    @Test
    void createZoneWithIncorrectBrandingBannerLink() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);
        Banner banner = new Banner();
        String backgroundColor = "#112233";
        String invalidUrl = "this_is_an_invalid_url";
        banner.setBackgroundColor(backgroundColor);
        banner.setLink(invalidUrl);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        MockHttpServletResponse response = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn().getResponse();

        assertThat(response.getContentAsString()).contains("Invalid banner link: " + invalidUrl + ". Must be a properly formatted URI beginning with http:// or https://");
    }

    @Test
    void updateZoneWithIncorrectBrandingBannerLink() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);
        Banner banner = new Banner();
        String backgroundColor = "#112233";
        String validUrl = "http://example.com";
        banner.setBackgroundColor(backgroundColor);
        banner.setLink(validUrl);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        String response = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        IdentityZone createdZone = JsonUtils.readValue(response, IdentityZone.class);
        String invalidUrl = "this_is_an_invalid_url";
        createdZone.getConfig().getBranding().getBanner().setLink(invalidUrl);

        MockHttpServletResponse mvcResult = mockMvc.perform(
                        put("/identity-zones/" + createdZone.getId())
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(createdZone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn()
                .getResponse();

        assertThat(mvcResult.getContentAsString()).contains("Invalid banner link: " + invalidUrl + ". Must be a properly formatted URI beginning with http:// or https://");
    }

    @Test
    void updateZoneWithConsent() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);

        BrandingInformation branding = new BrandingInformation();
        branding.setConsent(new Consent("some text", "http://localhost"));
        zone.getConfig().setBranding(branding);

        String response = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        IdentityZone createdZone = JsonUtils.readValue(response, IdentityZone.class);

        createdZone.getConfig().getBranding().getConsent().setText("some updated text");
        createdZone.getConfig().getBranding().getConsent().setLink("http://localhost/some-updated-link");

        MockHttpServletResponse mvcResult = mockMvc.perform(
                        put("/identity-zones/" + createdZone.getId())
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(createdZone)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse();

        IdentityZone updatedZone = JsonUtils.readValue(mvcResult.getContentAsString(), IdentityZone.class);

        Consent createdZoneConsent = updatedZone.getConfig().getBranding().getConsent();
        assertThat(createdZoneConsent.getText()).isEqualTo("some updated text");
        assertThat(createdZoneConsent.getLink()).isEqualTo("http://localhost/some-updated-link");
    }

    @Test
    void updateZoneWithOnlyConsentText() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);

        BrandingInformation branding = new BrandingInformation();
        branding.setConsent(new Consent("some text", "http://localhost"));
        zone.getConfig().setBranding(branding);

        String response = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        IdentityZone createdZone = JsonUtils.readValue(response, IdentityZone.class);

        createdZone.getConfig().getBranding().getConsent().setLink(null);

        MockHttpServletResponse mvcResult = mockMvc.perform(
                        put("/identity-zones/" + createdZone.getId())
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(createdZone)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse();

        IdentityZone updatedZone = JsonUtils.readValue(mvcResult.getContentAsString(), IdentityZone.class);

        Consent createdZoneConsent = updatedZone.getConfig().getBranding().getConsent();
        assertThat(createdZoneConsent.getText()).isEqualTo("some text");
        assertThat(createdZoneConsent.getLink()).isEqualTo((Object) null);
    }

    @Test
    void updateZoneWithNoConsentText() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);

        BrandingInformation branding = new BrandingInformation();
        branding.setConsent(new Consent("some text", "http://localhost"));
        zone.getConfig().setBranding(branding);

        String response = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        IdentityZone createdZone = JsonUtils.readValue(response, IdentityZone.class);

        createdZone.getConfig().getBranding().getConsent().setText(null);

        MockHttpServletResponse mvcResult = mockMvc.perform(
                        put("/identity-zones/" + createdZone.getId())
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(createdZone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn()
                .getResponse();

        assertThat(mvcResult.getContentAsString()).contains("Consent text must be set if configuring consent");
    }

    @Test
    void updateZoneWithInvalidConsentLink() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);

        BrandingInformation branding = new BrandingInformation();
        branding.setConsent(new Consent("some text", "http://localhost"));
        zone.getConfig().setBranding(branding);

        String response = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        IdentityZone createdZone = JsonUtils.readValue(response, IdentityZone.class);

        createdZone.getConfig().getBranding().getConsent().setText("some updated text");
        String invalidConsentLink = "not a valid link";
        createdZone.getConfig().getBranding().getConsent().setLink(invalidConsentLink);

        MockHttpServletResponse mvcResult = mockMvc.perform(
                        put("/identity-zones/" + createdZone.getId())
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(createdZone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn()
                .getResponse();

        assertThat(mvcResult.getContentAsString()).contains("Invalid consent link: " + invalidConsentLink + ". Must be a properly formatted URI beginning with http:// or https://");
    }

    @Test
    void createZoneWithInvalidBannerBackgroundColor() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);
        Banner banner = new Banner();
        String invalidColor = "#ZLKSWE";
        String validUrl = "http://example.com";
        banner.setBackgroundColor(invalidColor);
        banner.setLink(validUrl);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        MockHttpServletResponse mvcResult = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn().getResponse();

        assertThat(mvcResult.getContentAsString()).contains("Invalid banner background color: " + invalidColor + ". Must be a properly formatted hexadecimal color code.");
    }

    @Test
    void updateZoneWithInvalidBannerBackgroundColor() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);
        Banner banner = new Banner();
        String backgroundColor = "#112233";
        String validUrl = "http://example.com";
        banner.setBackgroundColor(backgroundColor);
        banner.setLink(validUrl);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        String response = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        IdentityZone createdZone = JsonUtils.readValue(response, IdentityZone.class);
        String invalidColor = "#ZLKSWE";
        createdZone.getConfig().getBranding().getBanner().setBackgroundColor(invalidColor);

        MockHttpServletResponse mvcResult = mockMvc.perform(
                        put("/identity-zones/" + createdZone.getId())
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(createdZone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn()
                .getResponse();

        assertThat(mvcResult.getContentAsString()).contains("Invalid banner background color: " + invalidColor + ". Must be a properly formatted hexadecimal color code.");
    }

    @Test
    void createZoneWithInvalidBannerTextColor() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);
        Banner banner = new Banner();
        String invalidColor = "#ZLKSWE";
        String validUrl = "http://example.com";
        banner.setTextColor(invalidColor);
        banner.setLink(validUrl);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        MockHttpServletResponse mvcResult = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn().getResponse();

        assertThat(mvcResult.getContentAsString()).contains("Invalid banner text color: " + invalidColor + ". Must be a properly formatted hexadecimal color code.");
    }

    @Test
    void updateZoneWithInvalidBannerTextColor() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);
        Banner banner = new Banner();
        String textColor = "#112233";
        String validUrl = "http://example.com";
        banner.setTextColor(textColor);
        banner.setLink(validUrl);
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        String response = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        IdentityZone createdZone = JsonUtils.readValue(response, IdentityZone.class);
        String invalidColor = "#ZLKSWE";
        createdZone.getConfig().getBranding().getBanner().setTextColor(invalidColor);

        MockHttpServletResponse mvcResult = mockMvc.perform(
                        put("/identity-zones/" + createdZone.getId())
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(createdZone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn()
                .getResponse();

        assertThat(mvcResult.getContentAsString()).contains("Invalid banner text color: " + invalidColor + ". Must be a properly formatted hexadecimal color code.");
    }

    @Test
    void createZoneWithInvalidBannerLogo() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);
        Banner banner = new Banner();
        String textColor = "#112233";
        String validUrl = "http://example.com";
        banner.setTextColor(textColor);
        banner.setLink(validUrl);
        banner.setLogo("NOT_BASE_64%");
        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        MockHttpServletResponse mvcResult = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn().getResponse();

        assertThat(mvcResult.getContentAsString()).contains("Invalid banner logo. Must be in BASE64 format.");
    }

    @Test
    void updateZoneWithInvalidBannerLogo() throws Exception {
        String id = UUID.randomUUID().toString();
        IdentityZone zone = createSimpleIdentityZone(id);
        Banner banner = new Banner();
        String textColor = "#112233";
        String validUrl = "http://example.com";
        banner.setTextColor(textColor);
        banner.setLink(validUrl);
        banner.setLogo("VALIDBASE64");

        BrandingInformation branding = new BrandingInformation();
        branding.setBanner(banner);
        zone.getConfig().setBranding(branding);

        String response = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(zone)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        IdentityZone createdZone = JsonUtils.readValue(response, IdentityZone.class);
        String invalidLogo = "INVALID_BASE_64%";
        createdZone.getConfig().getBranding().getBanner().setLogo(invalidLogo);

        MockHttpServletResponse mvcResult = mockMvc.perform(
                        put("/identity-zones/" + createdZone.getId())
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(createdZone)))
                .andExpect(status().isUnprocessableEntity())
                .andReturn()
                .getResponse();

        assertThat(mvcResult.getContentAsString()).contains("Invalid banner logo. Must be in BASE64 format.");
    }

    @Test
    void createZoneWithInvalidSamlKeyCertPair() throws Exception {

        String id = UUID.randomUUID().toString();
        IdentityZone identityZone = createSimpleIdentityZone(id);
        TokenPolicy tokenPolicy = new TokenPolicy(3600, 7200);
        Map<String, String> jwtKeys = new HashMap<>();
        jwtKeys.put("key_id_1", "secret_key_1");
        jwtKeys.put("key_id_2", "secret_key_2");
        tokenPolicy.setKeys(jwtKeys);
        tokenPolicy.setActiveKeyId("key_id_1");

        SamlConfig samlConfig = new SamlConfig();

        String samlPrivateKey = """
                -----BEGIN RSA PRIVATE KEY-----
                Proc-Type: 4,ENCRYPTED
                DEK-Info: DES-EDE3-CBC,5771044F3450A262
                
                VfRgIdzq/TUFdIwTOxochDs02sSQXA/Z6mRnffYTQMwXpQ5f5nRuqcY8zECGMaDe
                aLrndpWzGbxiePKgN5AxuIDYNnKMrDRgyCzaaPx66rb87oMwtuq1HM18qqs+yN5v
                CdsoS2uz57fCDI24BuJkIDSIeumLXc5MdN0HUeaxOVzmpbpsbBXjRYa24gW38mUh
                DzmOAsNDxfoSTox02Cj+GV024e+PiWR6AMA7RKhsKPf9F4ctWwozvEHrV8fzTy5B
                +KM361P7XwJYueiV/gMZW2DXSujNRBEVfC1CLaxDV3eVsFX5iIiUbc4JQYOM6oQ3
                KxGPImcRQPY0asKgEDIaWtysUuBoDSbfQ/FxGWeqwR6P/Vth4dXzVGheYLu1V1CU
                o6M+EXC/VUhERKwi13EgqXLKrDI352/HgEKG60EhM6xIJy9hLHy0UGjdHDcA+cF6
                NEl6E3CivddMHIPQWil5x4AMaevGa3v/gcZI0DN8t7L1g4fgjtSPYzvwmOxoxHGi
                7V7PdzaD4GWV75fv99sBlq2e0KK9crNUzs7vbFA/m6tgNA628SGhU1uAc/5xOskI
                0Ez6kjgHoh4U7t/fu7ey1MbFQt6byHY9lk27nW1ub/QMAaRJ+EDnrReB/NN6q5Vu
                h9eQNniNOeQfflzFyPB9omLNsVJkENn+lZNNrrlbn8OmJ0pT58Iaetfh79rDZPw9
                zmHVqmMynmecTWAcA9ATf7+lh+xV88JDjQkLcG/3WEXNH7HXKO00pUa8+JtyxbAb
                dAwGgrjJkbbk1qLLScOqY4mA5WXa5+80LMkCYO44vVTp2VKmnxj8Mw==
                -----END RSA PRIVATE KEY-----""";

        String samlKeyPassphrase = "password";

        String samlCertificate = """
                -----BEGIN CERTIFICATE-----
                MIIEbzCCA1egAwIBAgIQCTPRC15ZcpIxJwdwiMVDSjANBgkqhkiG9w0BAQUFADA2
                MQswCQYDVQQGEwJOTDEPMA0GA1UEChMGVEVSRU5BMRYwFAYDVQQDEw1URVJFTkEg
                U1NMIENBMB4XDTEzMDczMDAwMDAwMFoXDTE2MDcyOTIzNTk1OVowPzEhMB8GA1UE
                CxMYRG9tYWluIENvbnRyb2wgVmFsaWRhdGVkMRowGAYDVQQDExFlZHVyb2FtLmJi
                ay5hYy51azCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANrSBWTl56O2
                VJbahURgPznums43Nnn/smJ6cGywPu4mtJHUHSmONlBDTAWFS1fLkh8YHIQmdwYg
                FY4pHjZmKVtJ6ZOFhDNN1R2VMka4ZtREWn3XX8pUacol5KjEIh6U/FvMHyRv7sV5
                9J6JUK+n5R7ZsSu7XRi6TrT3xhfu0KoWo8RM/salKo2theIcyqLPHiFLEtA7ISLV
                q7I49uj9h9Hni/iCpBey+Gn5yDub4nrv81aDfD6zDoW/vXIOrcXFYRK3lXWOOFi4
                cfmu4SQQwMV1jBOer8JgfsQ3EQMgwauSMLUR31wPM83eMbOC72HhW9SJUtFDj42c
                PIEWd+rTA8ECAwEAAaOCAW4wggFqMB8GA1UdIwQYMBaAFAy9k2gM896ro0lrKzdX
                R+qQ47ntMB0GA1UdDgQWBBQgoU+Pbgk2MthczZt7TviUiIWyrjAOBgNVHQ8BAf8E
                BAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUH
                AwIwIgYDVR0gBBswGTANBgsrBgEEAbIxAQICHTAIBgZngQwBAgEwOgYDVR0fBDMw
                MTAvoC2gK4YpaHR0cDovL2NybC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5j
                cmwwbQYIKwYBBQUHAQEEYTBfMDUGCCsGAQUFBzAChilodHRwOi8vY3J0LnRjcy50
                ZXJlbmEub3JnL1RFUkVOQVNTTENBLmNydDAmBggrBgEFBQcwAYYaaHR0cDovL29j
                c3AudGNzLnRlcmVuYS5vcmcwHAYDVR0RBBUwE4IRZWR1cm9hbS5iYmsuYWMudWsw
                DQYJKoZIhvcNAQEFBQADggEBAHTw5b1lrTBqnx/QSO50Mww+OPYgV4b4NSu2rqxG
                I2hHLiD4l7Sk3WOdXPAQMmTlo6N10Lt6p8gLLxKsOAw+nK+z9aLcgKk9/kYoe4C8
                jHzwTy6eO+sCKnJfTqEX8p3b8l736lUWwPgMjjEN+d49ZegqCwH6SEz7h0+DwGmF
                LLfFM8J1SozgPVXgmfCv0XHpFyYQPhXligeWk39FouC2DfhXDTDOgc0n/UQjETNl
                r2Jawuw1VG6/+EFf4qjwr0/hIrxc/0XEd9+qLHKef1rMjb9pcZA7Dti+DoKHsxWi
                yl3DnNZlj0tFP0SBcwjg/66VAekmFtJxsLx3hKxtYpO3m8c=
                -----END CERTIFICATE-----""";

        samlConfig.setCertificate(samlCertificate);
        samlConfig.setPrivateKey(samlPrivateKey);
        samlConfig.setPrivateKeyPassword(samlKeyPassphrase);

        IdentityZoneConfiguration definition = new IdentityZoneConfiguration(tokenPolicy);
        identityZone.setConfig(definition.setSamlConfig(samlConfig));

        mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().isUnprocessableEntity());
    }

    @Test
    void delete_zone_cleans_db() throws Exception {
        IdentityProviderProvisioning idpp = webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class);
        ScimGroupProvisioning groupProvisioning = webApplicationContext.getBean(ScimGroupProvisioning.class);
        ScimUserProvisioning userProvisioning = webApplicationContext.getBean(ScimUserProvisioning.class);
        ScimGroupMembershipManager membershipManager = webApplicationContext.getBean(ScimGroupMembershipManager.class);
        ScimGroupExternalMembershipManager externalMembershipManager = webApplicationContext.getBean(ScimGroupExternalMembershipManager.class);
        ApprovalStore approvalStore = webApplicationContext.getBean(ApprovalStore.class);
        JdbcTemplate template = webApplicationContext.getBean(JdbcTemplate.class);

        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        //create zone and clients
        UaaClientDetails client =
                new UaaClientDetails("limited-client", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(UAA));
        client.addAdditionalInformation("foo", "bar");
        for (String url : Arrays.asList("", "/")) {
            mockMvc.perform(
                            post("/identity-zones/" + zone.getId() + "/clients" + url)
                                    .header("Authorization", "Bearer " + identityClientZonesReadToken)
                                    .contentType(APPLICATION_JSON)
                                    .accept(APPLICATION_JSON)
                                    .content(JsonUtils.writeValueAsString(client)))
                    .andExpect(status().isForbidden());
        }

        //create client without token
        mockMvc.perform(post("/identity-zones/" + zone.getId() + "/clients")
                        .contentType(APPLICATION_JSON)
                        .accept(APPLICATION_JSON)
                        .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isUnauthorized());

        MvcResult result = mockMvc.perform(
                        post("/identity-zones/" + zone.getId() + "/clients")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .accept(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated()).andReturn();
        UaaClientDetails created = JsonUtils.readValue(result.getResponse().getContentAsString(), UaaClientDetails.class);
        assertThat(created.getClientSecret()).isNull();
        assertThat(created.getAdditionalInformation())
                .containsEntry(ClientConstants.CREATED_WITH, "zones.write")
                .containsEntry(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(UAA))
                .containsEntry("foo", "bar");

        //ensure that UAA provider is there
        assertThat(idpp.retrieveByOrigin(UAA, zone.getId())).isNotNull();
        assertThat(idpp.retrieveByOrigin(UAA, zone.getId()).getOriginKey()).isEqualTo(UAA);

        //create login-server provider
        IdentityProvider provider = new IdentityProvider<>()
                .setOriginKey(LOGIN_SERVER)
                .setActive(true)
                .setIdentityZoneId(zone.getId())
                .setName("Delete Test")
                .setType(LOGIN_SERVER);
        IdentityZoneHolder.set(zone);
        provider = idpp.create(provider, provider.getIdentityZoneId());
        assertThat(idpp.retrieveByOrigin(LOGIN_SERVER, zone.getId())).isNotNull();
        assertThat(idpp.retrieveByOrigin(LOGIN_SERVER, zone.getId()).getId()).isEqualTo(provider.getId());

        //create user and add user to group
        ScimUser user = getScimUser();
        user.setOrigin(LOGIN_SERVER);
        user = userProvisioning.createUser(user, "", IdentityZoneHolder.get().getId());
        assertThat(userProvisioning.retrieve(user.getId(), IdentityZoneHolder.get().getId())).isNotNull();
        assertThat(user.getZoneId()).isEqualTo(zone.getId());

        //create group
        ScimGroup group = new ScimGroup("Delete Test Group");
        group.setZoneId(zone.getId());
        group = groupProvisioning.create(group, IdentityZoneHolder.get().getId());
        membershipManager.addMember(group.getId(), new ScimGroupMember(user.getId(), ScimGroupMember.Type.USER), IdentityZoneHolder.get().getId());
        assertThat(group.getZoneId()).isEqualTo(zone.getId());
        assertThat(groupProvisioning.retrieve(group.getId(), IdentityZoneHolder.get().getId())).isNotNull();
        assertThat(groupProvisioning.retrieve(group.getId(), IdentityZoneHolder.get().getId()).getDisplayName()).isEqualTo("Delete Test Group");
        assertThat(membershipManager.getMembers(group.getId(), false, IdentityZoneHolder.get().getId())).hasSize(1);

        //failed authenticated user
        mockMvc.perform(
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
        // assertThat(template.queryForObject("select count(*) from sec_audit where identity_zone_id=?", new Object[] {user.getZoneId()}, Integer.class), greaterThan(0))
        //create an external group map
        IdentityZoneHolder.set(zone);
        externalMembershipManager.mapExternalGroup(group.getId(), "externalDeleteGroup", LOGIN_SERVER, IdentityZoneHolder.get().getId());
        assertThat(externalMembershipManager.getExternalGroupMapsByGroupId(group.getId(), LOGIN_SERVER, IdentityZoneHolder.get().getId())).hasSize(1);
        assertThat(template.queryForObject("select count(*) from external_group_mapping where origin=?", Integer.class, new Object[]{LOGIN_SERVER})).isOne();

        //add user approvals
        approvalStore.addApproval(
                new Approval()
                        .setClientId(client.getClientId())
                        .setScope("openid")
                        .setStatus(Approval.ApprovalStatus.APPROVED)
                        .setUserId(user.getId()), IdentityZoneHolder.get().getId()
        );
        assertThat(approvalStore.getApprovals(user.getId(), client.getClientId(), IdentityZoneHolder.get().getId())).hasSize(1);

        //perform zone delete
        mockMvc.perform(
                        delete("/identity-zones/{id}", zone.getId())
                                .header("Authorization", "Bearer " + identityClientToken)
                                .accept(APPLICATION_JSON))
                .andExpect(status().isOk());

        mockMvc.perform(
                        delete("/identity-zones/{id}", zone.getId())
                                .header("Authorization", "Bearer " + identityClientToken)
                                .accept(APPLICATION_JSON))
                .andExpect(status().isNotFound());

        assertThat(template.queryForObject("select count(*) from identity_zone where id=?", Integer.class, new Object[]{zone.getId()})).isZero();
        assertThat(template.queryForObject("select count(*) from oauth_client_details where identity_zone_id=?", Integer.class, new Object[]{zone.getId()})).isZero();
        assertThat(template.queryForObject("select count(*) from " + dbUtils.getQuotedIdentifier("groups", template) + " where identity_zone_id=?", Integer.class, new Object[]{zone.getId()})).isZero();
        assertThat(template.queryForObject("select count(*) from sec_audit where identity_zone_id=?", Integer.class, new Object[]{zone.getId()})).isZero();
        assertThat(template.queryForObject("select count(*) from users where identity_zone_id=?", Integer.class, new Object[]{zone.getId()})).isZero();
        assertThat(template.queryForObject("select count(*) from external_group_mapping where origin=?", Integer.class, new Object[]{LOGIN_SERVER})).isZero();

        final String groupId = group.getId();
        String zoneId = IdentityZoneHolder.get().getId();
        assertThatThrownBy(() -> externalMembershipManager.getExternalGroupMapsByGroupId(groupId, LOGIN_SERVER, zoneId))
                .isInstanceOf(ScimResourceNotFoundException.class)
                .hasMessageContainingAll("Group", " does not exist");

        assertThat(template.queryForObject("select count(*) from authz_approvals where user_id=?", Integer.class, new Object[]{user.getId()})).isZero();
        assertThat(approvalStore.getApprovals(user.getId(), client.getClientId(), IdentityZoneHolder.get().getId())).isEmpty();
    }

    @Test
    void deleteZonePublishesEvent() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        uaaEventListener.clearEvents();

        ResultActions result = mockMvc.perform(
                        delete("/identity-zones/{id}", zone.getId())
                                .header("Authorization", "Bearer " + identityClientToken)
                                .accept(APPLICATION_JSON))
                .andExpect(status().isOk());
        IdentityZone deletedZone = JsonUtils.readValue(result.andReturn().getResponse().getContentAsString(), IdentityZone.class);
        assertThat(deletedZone.getConfig().getTokenPolicy().getKeys()).isEqualTo(emptyMap());
        assertThat(deletedZone.getConfig().getSamlConfig().getPrivateKey()).isNull();
        assertThat(deletedZone.getConfig().getSamlConfig().getPrivateKeyPassword()).isNull();
        assertThat(deletedZone.getConfig().getSamlConfig().getCertificate()).isEqualTo(SERVICE_PROVIDER_CERTIFICATE);

        assertThat(uaaEventListener.getEventCount()).isOne();
        AbstractUaaEvent event = uaaEventListener.getLatestEvent();
        assertThat(event).isInstanceOf(EntityDeletedEvent.class);
        EntityDeletedEvent<IdentityZone> deletedEvent = (EntityDeletedEvent<IdentityZone>) event;
        assertThat(deletedEvent.getDeleted()).isInstanceOf(IdentityZone.class);

        deletedZone = deletedEvent.getDeleted();
        assertThat(deletedZone.getId()).isEqualTo(id);
        assertThat(deletedEvent.getIdentityZoneId()).isEqualTo(id);
        String auditedIdentityZone = deletedEvent.getAuditEvent().getData();
        assertThat(auditedIdentityZone).contains(id);
    }

    @Test
    void deleteZoneShouldFailWhenIdpWithAliasExistsInZone() throws Exception {
        // create zone
        final String idzId = generator.generate();
        createZone(idzId, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        // create IdP with alias (via DB, since alias feature is disabled by default)
        final JdbcIdentityProviderProvisioning idpProvisioning = webApplicationContext
                .getBean(JdbcIdentityProviderProvisioning.class);
        final IdentityProvider<OIDCIdentityProviderDefinition> idp = new IdentityProvider<>();
        idp.setName("some-idp");
        idp.setId(UUID.randomUUID().toString());
        idp.setIdentityZoneId(idzId);
        idp.setOriginKey("some-origin-key");
        idp.setAliasZid(IdentityZone.getUaaZoneId());
        idp.setAliasId(UUID.randomUUID().toString());
        idp.setType(OriginKeys.OIDC10);
        idpProvisioning.create(idp, idzId);

        // deleting zone should fail
        mockMvc.perform(
                delete("/identity-zones/" + idzId)
                        .header("Authorization", "Bearer " + identityClientToken)
                        .accept(APPLICATION_JSON)
        ).andExpect(status().isUnprocessableEntity());
    }

    @Test
    void createAndDeleteLimitedClientInNewZoneUsingZoneEndpoint() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        UaaClientDetails client =
                new UaaClientDetails("limited-client", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(UAA));
        client.addAdditionalInformation("foo", "bar");
        for (String url : Arrays.asList("", "/")) {
            mockMvc.perform(
                            post("/identity-zones/" + zone.getId() + "/clients" + url)
                                    .header("Authorization", "Bearer " + identityClientZonesReadToken)
                                    .contentType(APPLICATION_JSON)
                                    .accept(APPLICATION_JSON)
                                    .content(JsonUtils.writeValueAsString(client)))
                    .andExpect(status().isForbidden());
        }

        MvcResult result = mockMvc.perform(
                        post("/identity-zones/" + zone.getId() + "/clients")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .accept(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isCreated()).andReturn();
        UaaClientDetails created = JsonUtils.readValue(result.getResponse().getContentAsString(), UaaClientDetails.class);
        assertThat(created.getClientSecret()).isNull();
        assertThat(created.getAdditionalInformation())
                .containsEntry(ClientConstants.CREATED_WITH, "zones.write")
                .containsEntry(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(UAA))
                .containsEntry("foo", "bar");
        checkAuditEventListener(1, AuditEventType.ClientCreateSuccess, clientCreateEventListener, id, "http://localhost:8080/uaa/oauth/token", "identity");

        for (String url : Arrays.asList("", "/")) {
            mockMvc.perform(
                            delete("/identity-zones/" + zone.getId() + "/clients/" + created.getClientId(), IdentityZone.getUaaZoneId() + url)
                                    .header("Authorization", "Bearer " + identityClientZonesReadToken)
                                    .accept(APPLICATION_JSON))
                    .andExpect(status().isForbidden());
        }
        mockMvc.perform(
                        delete("/identity-zones/" + zone.getId() + "/clients/" + created.getClientId(), IdentityZone.getUaaZoneId())
                                .header("Authorization", "Bearer " + identityClientToken)
                                .accept(APPLICATION_JSON))
                .andExpect(status().isOk());

        checkAuditEventListener(1, AuditEventType.ClientDeleteSuccess, clientDeleteEventListener, id, "http://localhost:8080/uaa/oauth/token", "identity");
    }

    @Test
    void createAndDeleteLimitedClientInUAAZoneReturns403() throws Exception {
        UaaClientDetails client =
                new UaaClientDetails("limited-client", null, "openid", GRANT_TYPE_AUTHORIZATION_CODE, "uaa.resource");
        client.setClientSecret("secret");
        client.addAdditionalInformation(ClientConstants.ALLOWED_PROVIDERS, Collections.singletonList(UAA));
        mockMvc.perform(
                        post("/identity-zones/uaa/clients")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .accept(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isForbidden());
        assertThat(clientCreateEventListener.getEventCount()).isZero();

        mockMvc.perform(
                        delete("/identity-zones/uaa/clients/admin")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .accept(APPLICATION_JSON))
                .andExpect(status().isForbidden());

        assertThat(clientDeleteEventListener.getEventCount()).isZero();
    }

    @Test
    void createAdminClientInNewZoneUsingZoneEndpointReturns400() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        UaaClientDetails client =
                new UaaClientDetails("admin-client", null, null, "client_credentials", "clients.write");
        client.setClientSecret("secret");
        mockMvc.perform(
                        post("/identity-zones/" + zone.getId() + "/clients")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .accept(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(client)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createsZonesWithDuplicateSubdomains() throws Exception {
        String subdomain = UUID.randomUUID().toString();
        String id1 = UUID.randomUUID().toString();
        String id2 = UUID.randomUUID().toString();
        IdentityZone identityZone1 = MultitenancyFixture.identityZone(id1, subdomain);
        IdentityZone identityZone2 = MultitenancyFixture.identityZone(id2, subdomain);
        mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .accept(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(identityZone1)))
                .andExpect(status().isCreated());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + identityClientToken)
                                .contentType(APPLICATION_JSON)
                                .accept(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(identityZone2)))
                .andExpect(status().isConflict());

        assertThat(zoneModifiedEventListener.getEventCount()).isOne();
    }

    @Test
    void zoneAdminTokenAgainstZoneEndpoints() throws Exception {
        String zone1 = generator.generate().toLowerCase();
        String zone2 = generator.generate().toLowerCase();

        IdentityZoneCreationResult result1 = MockMvcUtils.createOtherIdentityZoneAndReturnResult(zone1, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());
        IdentityZoneCreationResult result2 = MockMvcUtils.createOtherIdentityZoneAndReturnResult(zone2, mockMvc, webApplicationContext, null, IdentityZoneHolder.getCurrentZoneId());

        MvcResult result = mockMvc.perform(
                        get("/identity-zones")
                                .header("Authorization", "Bearer " + result1.getZoneAdminToken())
                                .header(IdentityZoneSwitchingFilter.HEADER, result1.getIdentityZone().getId())
                                .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn();

        //test read your own zone only
        List<IdentityZone> zones = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<>() {
        });
        assertThat(zones).hasSize(1);
        assertThat(zones.getFirst().getSubdomain()).isEqualTo(zone1);

        //test write your own
        mockMvc.perform(
                        put("/identity-zones/" + result1.getIdentityZone().getId())
                                .header("Authorization", "Bearer " + result1.getZoneAdminToken())
                                .header(IdentityZoneSwitchingFilter.HEADER, result1.getIdentityZone().getId())
                                .contentType(APPLICATION_JSON)
                                .accept(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(result1.getIdentityZone())))
                .andExpect(status().isOk());

        //test write someone elses
        mockMvc.perform(
                        put("/identity-zones/" + result2.getIdentityZone().getId())
                                .header("Authorization", "Bearer " + result1.getZoneAdminToken())
                                .header(IdentityZoneSwitchingFilter.HEADER, result1.getIdentityZone().getId())
                                .contentType(APPLICATION_JSON)
                                .accept(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(result2.getIdentityZone())))
                .andExpect(status().isForbidden());

        //test create as zone admin
        mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + result1.getZoneAdminToken())
                                .header(IdentityZoneSwitchingFilter.HEADER, result1.getIdentityZone().getId())
                                .contentType(APPLICATION_JSON)
                                .accept(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(result2.getIdentityZone())))
                .andExpect(status().isForbidden());

    }

    @Test
    void successfulUserManagementInZoneUsingAdminClient() throws Exception {
        String subdomain = generator.generate().toLowerCase();
        UaaClientDetails adminClient = new UaaClientDetails("admin", null, null, "client_credentials", "scim.read,scim.write");
        adminClient.setClientSecret("admin-secret");
        IdentityZoneCreationResult creationResult = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, adminClient, IdentityZoneHolder.getCurrentZoneId());
        IdentityZone identityZone = creationResult.getIdentityZone();

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);
        checkAuditEventListener(1, AuditEventType.GroupCreatedEvent, groupModifiedEventListener, IdentityZone.getUaaZoneId(), "http://localhost:8080/uaa/oauth/token", "identity");
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

        MvcResult result = mockMvc.perform(put)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userName").value(user.getUserName()))
                .andReturn();

        checkAuditEventListener(2, AuditEventType.UserModifiedEvent, userModifiedEventListener, identityZone.getId(), "http://" + subdomain + ".localhost:8080/uaa/oauth/token", "admin");
        user = JsonUtils.readValue(result.getResponse().getContentAsString(), ScimUser.class);
        List<ScimUser> users = getUsersInZone(subdomain, scimAdminToken);
        assertThat(users).containsExactly(user);

        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId())
                .header("Authorization", "Bearer " + scimAdminToken)
                .header("If-Match", "\"" + user.getVersion() + "\"")
                .contentType(APPLICATION_JSON)
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));

        mockMvc.perform(delete)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(user.getId()))
                .andReturn();

        checkAuditEventListener(3, AuditEventType.UserDeletedEvent, userModifiedEventListener, identityZone.getId(), "http://" + subdomain + ".localhost:8080/uaa/oauth/token", "admin");
        users = getUsersInZone(subdomain, scimAdminToken);
        assertThat(users).isEmpty();
    }

    @Test
    void createAndListUsersInOtherZoneIsUnauthorized() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        String defaultZoneAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write,scim.read");

        ScimUser user = getScimUser();

        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
                .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"))
                .header("Authorization", "Bearer " + defaultZoneAdminToken)
                .contentType(APPLICATION_JSON)
                .content(requestBody);

        mockMvc.perform(post).andExpect(status().isUnauthorized());

        MockHttpServletRequestBuilder get = get("/Users").header("Authorization", "Bearer " + defaultZoneAdminToken);
        if (subdomain != null && !"".equals(subdomain)) {
            get.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        }

        mockMvc.perform(get).andExpect(status().isUnauthorized()).andReturn();
    }

    @Test
    void modifyandDeleteUserInOtherZoneIsUnauthorized() throws Exception {
        String scimWriteToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        ScimUser user = createUser(scimWriteToken, null);

        String subdomain = generator.generate();
        MockMvcUtils.createOtherIdentityZone(subdomain, mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());

        checkZoneAuditEventInUaa(1, AuditEventType.IdentityZoneCreatedEvent);

        String scimAdminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "admin-secret", "scim.write,scim.read", subdomain);
        user.setUserName("updated-user@defaultzone.com");

        MockHttpServletRequestBuilder put = put("/Users/" + user.getId())
                .header("Authorization", "Bearer " + scimAdminToken)
                .header("If-Match", "\"" + user.getVersion() + "\"")
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(user));

        mockMvc.perform(put)
                .andExpect(status().isUnauthorized())
                .andReturn();

        MockHttpServletRequestBuilder delete = delete("/Users/" + user.getId())
                .header("Authorization", "Bearer " + scimAdminToken)
                .header("If-Match", "\"" + user.getVersion() + "\"")
                .contentType(APPLICATION_JSON);

        mockMvc.perform(delete)
                .andExpect(status().isUnauthorized())
                .andReturn();
    }

    @Test
    void userCanReadAZone_withZoneZoneIdReadToken() throws Exception {
        String scimWriteToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret", "scim.write");
        ScimUser user = createUser(scimWriteToken, null);

        String id = generator.generate().toLowerCase();
        IdentityZone identityZone = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());

        for (String displayName : Arrays.asList("read", "admin")) {
            ScimGroup group = new ScimGroup();
            String zoneReadScope = "zones." + identityZone.getId() + "." + displayName;
            group.setDisplayName(zoneReadScope);
            group.setMembers(Collections.singletonList(new ScimGroupMember(user.getId())));
            mockMvc.perform(
                            post("/Groups/zones")
                                    .header("Authorization", "Bearer " + identityClientToken)
                                    .contentType(APPLICATION_JSON)
                                    .accept(APPLICATION_JSON)
                                    .content(JsonUtils.writeValueAsString(group)))
                    .andExpect(status().isCreated());
        }

        String userAccessToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(), user.getPassword(), "zones." + identityZone.getId() + ".read");

        MvcResult result = mockMvc.perform(
                        get("/identity-zones/" + identityZone.getId())
                                .header("Authorization", "Bearer " + userAccessToken)
                                .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())
                                .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn();

        IdentityZone zoneResult = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<IdentityZone>() {
        });
        assertThat(zoneResult).isEqualTo(identityZone);
        assertThat(zoneResult.getConfig().getSamlConfig().getPrivateKey()).isNull();
        assertThat(zoneResult.getConfig().getTokenPolicy().getKeys()).isEqualTo(emptyMap());

        String userAccessTokenReadAndAdmin = MockMvcUtils.getUserOAuthAccessTokenAuthCode(mockMvc, "identity", "identitysecret", user.getId(), user.getUserName(), user.getPassword(), "zones." + identityZone.getId() + ".read " + "zones." + identityZone.getId() + ".admin ");
        result = mockMvc.perform(
                        get("/identity-zones/" + identityZone.getId())
                                .header("Authorization", "Bearer " + userAccessTokenReadAndAdmin)
                                .header(IdentityZoneSwitchingFilter.HEADER, identityZone.getId())
                                .accept(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn();

        zoneResult = JsonUtils.readValue(result.getResponse().getContentAsString(), new TypeReference<IdentityZone>() {
        });
        assertThat(zoneResult).isEqualTo(identityZone);
        assertThat(zoneResult.getConfig().getSamlConfig())
                .returns(null, SamlConfig::getPrivateKey)
                .returns(null, SamlConfig::getPrivateKeyPassword)
                .returns(SERVICE_PROVIDER_CERTIFICATE, SamlConfig::getCertificate);
        assertThat(zoneResult.getConfig().getTokenPolicy())
                .returns("kid", TokenPolicy::getActiveKeyId)
                .returns(emptyMap(), TokenPolicy::getKeys);
    }

    @Test
    void updateZoneWithDifferentIdInBodyAndPath_fails() throws Exception {
        IdentityZone identityZone = createZone(new AlphanumericRandomValueStringGenerator(5).generate(), HttpStatus.CREATED, adminToken, new IdentityZoneConfiguration());
        String id = identityZone.getId();
        IdentityZone identityZone2 = createZone(new AlphanumericRandomValueStringGenerator(5).generate(), HttpStatus.CREATED, adminToken, new IdentityZoneConfiguration());
        identityZone.setId(identityZone2.getId());

        updateZone(id, identityZone, HttpStatus.UNPROCESSABLE_ENTITY, adminToken);
    }

    @Test
    void createZoneWithCustomIssuerAndSigningKeyWorks() throws Exception {
        IdentityZoneConfiguration identityZoneConfiguration = new IdentityZoneConfiguration();
        identityZoneConfiguration.setIssuer("http://my-custom-issuer.com");
        identityZoneConfiguration.setTokenPolicy(new TokenPolicy());

        createZone(
                "should-not-exist" + new AlphanumericRandomValueStringGenerator(5).generate(),
                HttpStatus.CREATED,
                adminToken,
                identityZoneConfiguration
        );
    }

    @Test
    void createZoneWithCustomIssuerAndNoTokenPolicyShouldFail() throws Exception {
        IdentityZoneConfiguration identityZoneConfiguration = new IdentityZoneConfiguration();
        identityZoneConfiguration.setIssuer("http://my-custom-issuer.com");
        identityZoneConfiguration.setTokenPolicy(null);

        createZone(
                "should-not-exist" + new AlphanumericRandomValueStringGenerator(5).generate(),
                HttpStatus.UNPROCESSABLE_ENTITY,
                "You cannot set issuer value unless you have set your own signing key for this identity zone.",
                adminToken,
                identityZoneConfiguration
        );
    }

    @Test
    void createZoneWithCustomIssuerAndNoActiveSigningKeyShouldFail() throws Exception {
        IdentityZoneConfiguration identityZoneConfiguration = new IdentityZoneConfiguration();
        identityZoneConfiguration.setIssuer("http://my-custom-issuer.com");
        identityZoneConfiguration.setTokenPolicy(new TokenPolicy());

        createZone(
                "should-not-exist" + new AlphanumericRandomValueStringGenerator(5).generate(),
                HttpStatus.UNPROCESSABLE_ENTITY,
                "You cannot set issuer value unless you have set your own signing key for this identity zone.",
                adminToken,
                identityZoneConfiguration
        );
    }

    @Test
    void updateZoneWithCustomIssuerAndSigningKeyWorks() throws Exception {
        IdentityZoneConfiguration identityZoneConfiguration = new IdentityZoneConfiguration();
        identityZoneConfiguration.setIssuer("http://my-custom-issuer.com");
        identityZoneConfiguration.setTokenPolicy(new TokenPolicy());

        String zoneId = "should-not-exist" + new AlphanumericRandomValueStringGenerator(5).generate();
        IdentityZone identityZone = createZone(zoneId, HttpStatus.CREATED, adminToken, identityZoneConfiguration);
        updateZone(zoneId, identityZone, HttpStatus.OK, adminToken);
    }

    @Test
    void updateZoneWithCustomIssuerSetAndNoTokenPolicyShouldFail() throws Exception {
        IdentityZoneConfiguration identityZoneConfiguration = new IdentityZoneConfiguration();
        identityZoneConfiguration.setIssuer("http://my-custom-issuer.com");
        identityZoneConfiguration.setTokenPolicy(new TokenPolicy());

        String zoneId = "should-not-exist" + new AlphanumericRandomValueStringGenerator(5).generate();
        IdentityZone identityZone = createZone(zoneId, HttpStatus.CREATED, adminToken, identityZoneConfiguration);

        identityZone.getConfig().setTokenPolicy(null);
        updateZone(zoneId, identityZone, HttpStatus.UNPROCESSABLE_ENTITY, "You cannot set issuer value unless you have set your own signing key for this identity zone.", adminToken);
    }

    @Test
    void updateZoneWithCustomIssuerSetAndNoActiveSigningKeyShouldFail() throws Exception {
        IdentityZoneConfiguration identityZoneConfiguration = new IdentityZoneConfiguration();
        identityZoneConfiguration.setIssuer("http://my-custom-issuer.com");
        identityZoneConfiguration.setTokenPolicy(new TokenPolicy());

        String zoneId = "should-not-exist" + new AlphanumericRandomValueStringGenerator(5).generate();
        IdentityZone identityZone =
                createZone(
                        zoneId,
                        HttpStatus.CREATED,
                        adminToken,
                        identityZoneConfiguration
                );

        identityZone.getConfig().setTokenPolicy(new TokenPolicy());
        updateZone(
                zoneId,
                identityZone,
                HttpStatus.UNPROCESSABLE_ENTITY,
                "You cannot set issuer value unless you have set your own signing key for this identity zone.",
                adminToken
        );
    }

    @Test
    void createZoneWithDefaultIdp() throws Exception {
        IdentityZoneConfiguration identityZoneConfiguration = new IdentityZoneConfiguration();
        identityZoneConfiguration.setDefaultIdentityProvider("originkey");
        IdentityZone zone = createZone(generator.generate().toLowerCase(), HttpStatus.CREATED, uaaAdminClientToken, identityZoneConfiguration);
        assertThat(zone.getConfig().getDefaultIdentityProvider()).isEqualTo("originkey");
    }

    private IdentityZone createZoneReturn() throws Exception {
        String id = generator.generate();
        IdentityZone zone = createZone(id, HttpStatus.CREATED, identityClientToken, new IdentityZoneConfiguration());
        assertThat(zone.getId()).isEqualTo(id);
        assertThat(zone.getSubdomain()).isEqualTo(id.toLowerCase());
        assertThat(zone.getConfig().getTokenPolicy().isRefreshTokenUnique()).isFalse();
        assertThat(zone.getConfig().getTokenPolicy().isRefreshTokenRotate()).isFalse();
        assertThat(zone.getConfig().getTokenPolicy().getRefreshTokenFormat()).isEqualTo(OPAQUE.getStringValue());
        checkAuditEventListener(1, AuditEventType.IdentityZoneCreatedEvent, zoneModifiedEventListener, IdentityZone.getUaaZoneId(), "http://localhost:8080/uaa/oauth/token", "identity");

        //validate that default groups got created
        ScimGroupProvisioning groupProvisioning = webApplicationContext.getBean(ScimGroupProvisioning.class);
        for (String g : UserConfig.DEFAULT_ZONE_GROUPS) {
            assertThat(groupProvisioning.getByName(g, id)).isNotNull();
        }
        return zone;
    }

    private ScimUser createUser(String token, String subdomain) throws Exception {
        ScimUser user = getScimUser();

        byte[] requestBody = JsonUtils.writeValueAsBytes(user);
        MockHttpServletRequestBuilder post = post("/Users")
                .header("Authorization", "Bearer " + token)
                .contentType(APPLICATION_JSON)
                .content(requestBody);
        if (subdomain != null && !subdomain.isEmpty()) {
            post.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        }

        MvcResult result = mockMvc.perform(post)
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

    private IdentityZone createZoneUsingToken(String token) throws Exception {
        return createZone(generator.generate().toLowerCase(), HttpStatus.CREATED, token, new IdentityZoneConfiguration());
    }

    private IdentityZone getIdentityZone(String id, HttpStatus expect, String token) throws Exception {
        MvcResult result = mockMvc.perform(
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
        Map<String, String> keys = new HashMap<>();
        keys.put("kid", "key");
        zoneConfiguration.getTokenPolicy().setKeys(keys);
        zoneConfiguration.getTokenPolicy().setActiveKeyId("kid");
        zoneConfiguration.getTokenPolicy().setKeys(keys);

        return createZone(id, expect, "", token, zoneConfiguration);
    }

    private IdentityZone createZone(String id, HttpStatus expect, String expectedContent, String token, IdentityZoneConfiguration zoneConfiguration) throws Exception {
        IdentityZone identityZone = createSimpleIdentityZone(id);
        identityZone.setConfig(zoneConfiguration);
        identityZone.getConfig().getSamlConfig().setPrivateKey(SERVICE_PROVIDER_KEY);
        identityZone.getConfig().getSamlConfig().setPrivateKeyPassword(SERVICE_PROVIDER_KEY_PASSWORD);
        identityZone.getConfig().getSamlConfig().setCertificate(SERVICE_PROVIDER_CERTIFICATE);

        MvcResult result = mockMvc.perform(
                        post("/identity-zones")
                                .header("Authorization", "Bearer " + token)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(identityZone)))
                .andExpect(status().is(expect.value()))
                .andExpect(content().string(containsString(expectedContent)))
                .andReturn();

        if (expect.is2xxSuccessful()) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityZone.class);
        }
        return null;
    }

    private IdentityZone updateZone(String id, IdentityZone identityZone, HttpStatus expect, String expectedContent, String token) throws Exception {
        MvcResult result = mockMvc.perform(
                        put("/identity-zones/" + id)
                                .header("Authorization", "Bearer " + token)
                                .contentType(APPLICATION_JSON)
                                .content(JsonUtils.writeValueAsString(identityZone)))
                .andDo(print())
                .andExpect(status().is(expect.value()))
                .andExpect(content().string(containsString(expectedContent)))
                .andReturn();

        if (expect.is2xxSuccessful()) {
            return JsonUtils.readValue(result.getResponse().getContentAsString(), IdentityZone.class);
        }
        return null;
    }

    private IdentityZone updateZone(String id, IdentityZone identityZone, HttpStatus expect, String token) throws Exception {
        return updateZone(id, identityZone, expect, "", token);
    }

    private IdentityZone updateZone(IdentityZone identityZone, HttpStatus expect, String token) throws Exception {
        return updateZone(identityZone.getId(), identityZone, expect, token);
    }

    private void checkZoneAuditEventInUaa(int eventCount, AuditEventType eventType) {
        checkAuditEventListener(eventCount, eventType, zoneModifiedEventListener, IdentityZone.getUaaZoneId(), "http://localhost:8080/uaa/oauth/token", "identity");
    }

    private <T extends AbstractUaaEvent> void checkAuditEventListener(int eventCount, AuditEventType eventType, TestApplicationEventListener<T> eventListener, String identityZoneId, String issuer, String subject) {
        T event = eventListener.getLatestEvent();
        assertThat(eventListener.getEventCount()).isEqualTo(eventCount);
        if (eventCount > 0) {
            assertThat(event.getAuditEvent().getType()).isEqualTo(eventType);
            assertThat(event.getAuditEvent().getIdentityZoneId()).isEqualTo(identityZoneId);
            String origin = event.getAuditEvent().getOrigin();
            if (hasText(origin) && !origin.contains("opaque-token=present")) {
                assertThat(origin)
                        .contains("iss=" + issuer)
                        .contains("sub=" + subject);
            }
        }
    }

    private IdentityZone createSimpleIdentityZone(String id) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(hasText(id) ? id : new AlphanumericRandomValueStringGenerator().generate());
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    private List<ScimUser> getUsersInZone(String subdomain, String token) throws Exception {
        MockHttpServletRequestBuilder get = get("/Users").header("Authorization", "Bearer " + token);
        if (subdomain != null && !subdomain.isEmpty()) {
            get.with(new SetServerNameRequestPostProcessor(subdomain + ".localhost"));
        }

        MvcResult mvcResult = mockMvc.perform(get).andExpect(status().isOk()).andReturn();
        JsonNode root = JsonUtils.readTree(mvcResult.getResponse().getContentAsString());
        return JsonUtils.readValue(root.get("resources").toString(), new TypeReference<List<ScimUser>>() {
        });
    }
}
