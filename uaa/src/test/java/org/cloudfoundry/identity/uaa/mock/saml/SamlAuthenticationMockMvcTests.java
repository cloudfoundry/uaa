package org.cloudfoundry.identity.uaa.mock.saml;

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.authentication.SamlResponseLoggerBinding;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.InterceptingLogger;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.JdbcSamlServiceProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.context.WebApplicationContext;
import org.xml.sax.InputSource;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static com.beust.jcommander.internal.Lists.newArrayList;
import static org.apache.logging.log4j.Level.DEBUG;
import static org.apache.logging.log4j.Level.WARN;
import static org.cloudfoundry.identity.uaa.authentication.SamlResponseLoggerBinding.X_VCAP_REQUEST_ID_HEADER;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createClient;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getUaaSecurityContext;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.oauth2.common.OAuth2AccessToken.ACCESS_TOKEN;
import static org.springframework.security.oauth2.common.OAuth2AccessToken.REFRESH_TOKEN;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class SamlAuthenticationMockMvcTests {

    private RandomValueStringGenerator generator;

    private IdentityZone spZone;
    private IdentityZone idpZone;
    private String spZoneEntityId;
    private IdentityProvider<SamlIdentityProviderDefinition> idp;
    private SamlServiceProvider samlServiceProvider;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private JdbcScimUserProvisioning jdbcScimUserProvisioning;
    @SpyBean
    private JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;

    @Autowired
    private LoggingAuditService loggingAuditService;
    private InterceptingLogger testLogger;
    private Logger originalAuditServiceLogger;

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @BeforeEach
    void createSamlRelationship(
            @Autowired JdbcSamlServiceProviderProvisioning jdbcSamlServiceProviderProvisioning,
            @Autowired JdbcScimUserProvisioning jdbcScimUserProvisioning
    ) throws Exception {
        generator = new RandomValueStringGenerator();
        BaseClientDetails adminClient = new BaseClientDetails("admin", "", "", "client_credentials", "uaa.admin");
        adminClient.setClientSecret("adminsecret");
        spZone = createZone("uaa-acting-as-saml-proxy-zone-", adminClient);
        idpZone = createZone("uaa-acting-as-saml-idp-zone-", adminClient);
        spZoneEntityId = spZone.getSubdomain() + ".cloudfoundry-saml-login";
        createSp(jdbcSamlServiceProviderProvisioning);
        createUser(jdbcScimUserProvisioning, idpZone);
    }

    @BeforeEach
    void installTestLogger() {
        testLogger = new InterceptingLogger();
        originalAuditServiceLogger = loggingAuditService.getLogger();
        loggingAuditService.setLogger(testLogger);
    }

    @AfterEach
    void putBackOriginalLogger() {
        loggingAuditService.setLogger(originalAuditServiceLogger);
    }

    @Test
    void sendAuthnRequestToIdp() throws Exception {
        createIdp();

        Mockito.verify(jdbcIdentityProviderProvisioning, times(1)).retrieveActive(spZone.getId());

        String idpEntityId = idpZone.getSubdomain() + ".cloudfoundry-saml-login";
        MvcResult mvcResult = mockMvc.perform(
                get("/uaa/saml/discovery")
                        .contextPath("/uaa")
                        .header(HOST, spZone.getSubdomain() + ".localhost:8080")
                        .param("returnIDParam", "idp")
                        .param("entityID", spZoneEntityId)
                        .param("idp", idp.getOriginKey())
                        .param("isPassive", "true")
        )
                .andExpect(status().isFound())
                .andReturn();

        Mockito.verify(jdbcIdentityProviderProvisioning, times(2)).retrieveActive(spZone.getId());

        mvcResult = mockMvc.perform(
                get(mvcResult.getResponse().getRedirectedUrl())
                        .contextPath("/uaa")
                        .header(HOST, spZone.getSubdomain() + ".localhost:8080")
                        .session((MockHttpSession) mvcResult.getRequest().getSession())

        )
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();

        Mockito.verify(jdbcIdentityProviderProvisioning, times(3)).retrieveActive(spZone.getId());

        String body = mvcResult.getResponse().getContentAsString();
        String relayState = extractRelayState(body);
        String samlRequest = extractSamlRequest(body);
        mockMvc.perform(
                post("/uaa/saml/idp/SSO/alias/" + idpEntityId)
                        .contextPath("/uaa")
                        .header(HOST, idpZone.getSubdomain() + ".localhost:8080")
                        .param("RelayState", relayState)
                        .param("SAMLRequest", samlRequest)
        )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://" + idpZone.getSubdomain() + ".localhost:8080/uaa/login"));
    }

    @Test
    void validateStaticAttributes(
            @Autowired JdbcSamlServiceProviderProvisioning jdbcSamlServiceProviderProvisioning
    ) throws Exception {
        createIdp();

        samlServiceProvider.getConfig().getStaticCustomAttributes().put("portal_id", "portal");
        samlServiceProvider.getConfig().getStaticCustomAttributes().put("portal_emails", Arrays.asList("portal1@portal.test", "portal2@portal.test"));
        jdbcSamlServiceProviderProvisioning.update(samlServiceProvider, idpZone.getId());

        String samlResponse = performIdpAuthentication();
        String xml = extractAssertion(samlResponse, true);
        XPath xpath = XPathFactory.newInstance().newXPath();
        String emails = (String) xpath.evaluate("//*[local-name()='Attribute'][@*[local-name()='Name' and .='portal_emails']]", new InputSource(new StringReader(xml)), XPathConstants.STRING);
        assertThat(emails, containsString("portal1@portal.test"));
        assertThat(emails, containsString("portal2@portal.test"));
    }

    @Test
    void validateCustomEmailAttribute(
            @Autowired JdbcSamlServiceProviderProvisioning jdbcSamlServiceProviderProvisioning
    ) throws Exception {
        createIdp();

        samlServiceProvider.getConfig().getAttributeMappings().put("email", "primary-email");
        jdbcSamlServiceProviderProvisioning.update(samlServiceProvider, idpZone.getId());

        String samlResponse = performIdpAuthentication();
        String xml = extractAssertion(samlResponse, true);
        XPath xpath = XPathFactory.newInstance().newXPath();
        String emails = (String) xpath.evaluate("//*[local-name()='Attribute'][@*[local-name()='Name' and .='primary-email']]", new InputSource(new StringReader(xml)), XPathConstants.STRING);
        assertThat(emails, equalTo("test@test.org"));
    }

    @Test
    void spIsAuthenticated() throws Exception {
        createIdp();

        String samlResponse = performIdpAuthentication();
        String xml = extractAssertion(samlResponse, false);

        testLogger.reset();

        postSamlResponse(xml)
                .andExpect(authenticated());

        assertThat(testLogger.getMessageCount(), is(3));

        ScimUser createdUser = jdbcScimUserProvisioning.retrieveAll(spZone.getId())
                .stream().filter(dbUser -> dbUser.getUserName().equals("marissa")).findFirst().get();

        String userCreatedLogMessage = testLogger.getFirstLogMessageOfType(AuditEventType.UserCreatedEvent);
        String expectedMessage = String.format(
                "UserCreatedEvent ('[\"user_id=%s\",\"username=marissa\"]'): principal=%s, origin=[caller=null], identityZoneId=[%s]",
                createdUser.getId(), createdUser.getId(), spZone.getId()
        );

        assertThat(userCreatedLogMessage, is(expectedMessage));
    }

    // see also similar test for LDAP in AbstractLdapMockMvcTest.java
    @Test
    void passcodeGrantIdTokenContainsExternalGroupsAsRolesClaim() throws Exception {
        createIdp((idpDefinition) -> {
            // External groups will only appear as roles if they are whitelisted
            idpDefinition.setExternalGroupsWhitelist(newArrayList("*"));
            // External groups are currently only stored in the db if StoreCustomAttributes is true
            idpDefinition.setStoreCustomAttributes(true);
            // External groups will only be found when there is a configured attribute name for them
            Map<String, Object> attributeMappings = new HashMap<>();
            attributeMappings.put("external_groups", Collections.singletonList("authorities"));
            idpDefinition.setAttributeMappings(attributeMappings);
        });

        String[] expectedExternalGroups = new String[]{"marissagroup1", "marissagroup2"};
        List<String> samlAuthorityNamesForMockAuthentication = newArrayList(expectedExternalGroups);

        // You need the openid scope in order to get an id_token,
        // and you need the roles scope in order to have the "roles" claim included into the id_token,
        // so we put both of these scopes on the client.
        String clientId = "roles_test_client";
        createClient(webApplicationContext,
                new BaseClientDetails(clientId, null, "roles,openid", "password,refresh_token", null),
                spZone
        );

        String spZoneHost = spZone.getSubdomain() + ".localhost:8080";

        // Log in to get a session cookie as the user
        String samlResponse = performIdpAuthentication(samlAuthorityNamesForMockAuthentication);
        String xml = extractAssertion(samlResponse, false);
        MockHttpSession session = (MockHttpSession) postSamlResponse(xml)
                .andExpect(authenticated())
                .andReturn().getRequest().getSession(false);

        // Using the user's session cookie, get a one-time passcode
        String content = mockMvc.perform(
                get("/passcode")
                        .session(session)
                        .header(HOST, spZoneHost)
                        .accept(APPLICATION_JSON)
        )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String passcode = JsonUtils.readValue(content, String.class);

        // Using the passcode, perform a password grant to get back tokens
        String response = mockMvc.perform(
                post("/oauth/token")
                        .param("client_id", clientId)
                        .param("client_secret", "")
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                        .param("passcode", passcode)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .header(HOST, spZoneHost)
        )
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> tokens = JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {
        });

        String accessToken = (String) tokens.get(ACCESS_TOKEN);
        Jwt accessTokenJwt = JwtHelper.decode(accessToken);
        Map<String, Object> accessTokenClaims = JsonUtils.readValue(accessTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        List<String> accessTokenScopes = (List<String>) accessTokenClaims.get("scope");
        // Check that the user had the roles scope, which is a pre-requisite for getting roles returned in the id_token
        assertThat(accessTokenScopes, hasItem("roles"));

        Jwt idTokenJwt = JwtHelper.decode((String) tokens.get("id_token"));
        Map<String, Object> claims = JsonUtils.readValue(idTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        List<String> idTokenRoles = (List<String>) claims.get("roles");
        assertThat(idTokenRoles, containsInAnyOrder(expectedExternalGroups));

        // As an aside, the /userinfo endpoint should also return the user's roles
        String userInfoContent = mockMvc.perform(
                get("/userinfo")
                        .header(HOST, spZoneHost)
                        .header("Authorization", "Bearer " + accessToken)
                        .accept(APPLICATION_JSON)
        )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        Map<String, Object> userInfo = JsonUtils.readValue(userInfoContent, new TypeReference<Map<String, Object>>() {
        });
        List<String> userInfoRoles = (List<String>) userInfo.get("roles");
        assertThat(userInfoRoles, containsInAnyOrder(expectedExternalGroups));

        // We also got back a refresh token. When they use it, the refreshed id_token should also have the roles claim.
        String refreshToken = (String) tokens.get(REFRESH_TOKEN);
        String refreshTokenResponse = mockMvc.perform(
                post("/oauth/token")
                        .param("client_id", clientId)
                        .param("client_secret", "")
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN)
                        .param("refresh_token", refreshToken)
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .header(HOST, spZoneHost)
        )
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> refreshedTokens = JsonUtils.readValue(refreshTokenResponse, new TypeReference<Map<String, Object>>() {
        });
        Jwt refreshedIdTokenJwt = JwtHelper.decode((String) refreshedTokens.get("id_token"));
        Map<String, Object> refreshedClaims = JsonUtils.readValue(refreshedIdTokenJwt.getClaims(), new TypeReference<Map<String, Object>>() {
        });
        List<String> refreshedIdTokenRoles = (List<String>) refreshedClaims.get("roles");
        assertThat(refreshedIdTokenRoles, containsInAnyOrder(expectedExternalGroups));
    }

    private ResultActions postSamlResponse(
            final String xml
    ) throws Exception {
        return postSamlResponse(xml, "", "", "");
    }

    private ResultActions postSamlResponse(
            final String xml,
            final String queryString,
            final String content,
            final String xVcapRequestId
    ) throws Exception {
        return mockMvc.perform(
                post("/uaa/saml/SSO/alias/" + spZoneEntityId + queryString)
                        .contextPath("/uaa")
                        .header(HOST, spZone.getSubdomain() + ".localhost:8080")
                        .header(CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .header(X_VCAP_REQUEST_ID_HEADER, xVcapRequestId)
                        .content(content)
                        .param("SAMLResponse", xml)
        );
    }

    @Nested
    @DefaultTestContext
    class WithCustomLogAppender {
        private List<LogEvent> logEvents;
        private AbstractAppender appender;
        private Level originalLevel;

        @BeforeEach
        void setupLogger() throws Exception {
            logEvents = new ArrayList<>();
            appender = new AbstractAppender("", null, null) {
                @Override
                public void append(LogEvent event) {
                    if (SamlResponseLoggerBinding.class.getName().equals(event.getLoggerName())) {
                        logEvents.add(event);
                    }
                }
            };
            appender.start();

            LoggerContext context = (LoggerContext) LogManager.getContext(false);
            originalLevel = context.getRootLogger().getLevel();
            Configurator.setRootLevel(DEBUG);
            context.getRootLogger().addAppender(appender);

            createIdp();
        }

        @AfterEach
        void removeAppender() {
            LoggerContext context = (LoggerContext) LogManager.getContext(false);
            context.getRootLogger().removeAppender(appender);
            Configurator.setRootLevel(originalLevel);
        }

        @Test
        void malformedSamlRequestLogsQueryStringAndContentMetadata() throws Exception {
            performIdpAuthentication();

            postSamlResponse(null, "?bogus=query", "someKey=someVal&otherKey=otherVal&emptyKey=", "vcap_request_id_abc123");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (bogus/5) (emptyKey/0) (SAMLResponse/0) (someKey/7) (otherKey/8), Content-type: application/x-www-form-urlencoded, Request-size: 43, X-Vcap-Request-Id: vcap_request_id_abc123");
        }

        @Test
        void malformedSamlRequestWithNoQueryStringAndNoContentMetadata() throws Exception {
            performIdpAuthentication();

            postSamlResponse(null, "", "", "");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (SAMLResponse/0), Content-type: application/x-www-form-urlencoded, Request-size: 0, X-Vcap-Request-Id: ");
        }

        @Test
        void malformedSamlRequestWithRepeatedParams() throws Exception {
            performIdpAuthentication();

            postSamlResponse(null, "?foo=a&foo=ab&foo=aaabbbccc", "", "");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (foo/1) (foo/2) (foo/9) (SAMLResponse/0), Content-type: application/x-www-form-urlencoded, Request-size: 0, X-Vcap-Request-Id: ");
        }

        private void assertThatMessageWasLogged(
                final List<LogEvent> logEvents,
                final Level expectedLevel,
                final String expectedMessage
        ) {
            assertThat(logEvents, hasItem(new MatchesLogEvent(expectedLevel, expectedMessage)));
        }
    }

    private static class MatchesLogEvent extends BaseMatcher<LogEvent> {

        private final Level expectedLevel;
        private final String expectedMessage;

        public MatchesLogEvent(
                final Level expectedLevel,
                final String expectedMessage
        ) {
            this.expectedLevel = expectedLevel;
            this.expectedMessage = expectedMessage;
        }

        @Override
        public boolean matches(Object actual) {
            if (!(actual instanceof LogEvent)) {
                return false;
            }
            LogEvent logEvent = (LogEvent) actual;

            return expectedLevel.equals(logEvent.getLevel())
                    && expectedMessage.equals(logEvent.getMessage().getFormattedMessage());
        }

        @Override
        public void describeTo(Description description) {
            description.appendText(String.format("LogEvent with level of {%s} and message of {%s}", this.expectedLevel, this.expectedMessage));
        }
    }

    private String performIdpAuthentication() throws Exception {
        return performIdpAuthentication(Collections.singletonList("uaa.user"));
    }

    private String performIdpAuthentication(List<String> authorityNames) throws Exception {
        List<GrantedAuthority> grantedAuthorityList = authorityNames.stream().map(UaaAuthority::authority).collect(Collectors.toList());
        RequestPostProcessor marissa = securityContext(getUaaSecurityContext("marissa", webApplicationContext, idpZone.getId(), grantedAuthorityList));
        return mockMvc.perform(
                get("/saml/idp/initiate")
                        .header("Host", idpZone.getSubdomain() + ".localhost")
                        .param("sp", spZoneEntityId)
                        .with(marissa)
        )
                .andDo(print())
                .andReturn().getResponse().getContentAsString();
    }

    private String getSamlMetadata(String subdomain, String url) throws Exception {
        return mockMvc.perform(
                get(url)
                        .header("Host", subdomain + ".localhost")
        )
                .andReturn().getResponse().getContentAsString();
    }

    private static void createUser(
            JdbcScimUserProvisioning jdbcScimUserProvisioning,
            IdentityZone identityZone
    ) {
        ScimUser user = new ScimUser(null, "marissa", "first", "last");
        user.setPrimaryEmail("test@test.org");
        jdbcScimUserProvisioning.createUser(user, "secret", identityZone.getId());
    }

    private void createSp(SamlServiceProviderProvisioning spProvisioning) throws Exception {
        SamlServiceProviderDefinition spDefinition = new SamlServiceProviderDefinition();
        spDefinition.setEnableIdpInitiatedSso(true);
        spDefinition.setMetaDataLocation(getSamlMetadata(spZone.getSubdomain(), "/saml/metadata"));
        Map<String, Object> staticAttributes = new HashMap<>();
        spDefinition.setStaticCustomAttributes(staticAttributes);
        samlServiceProvider = new SamlServiceProvider()
                .setIdentityZoneId(idpZone.getId())
                .setEntityId(spZoneEntityId)
                .setConfig(spDefinition)
                .setActive(true)
                .setName("SAML SP for Mock Tests");
        samlServiceProvider = spProvisioning.create(samlServiceProvider, idpZone.getId());
    }

    void createIdp() throws Exception {
        createIdp(null);
    }

    private void createIdp(Consumer<SamlIdentityProviderDefinition> additionalConfigCallback) throws Exception {
        idp = new IdentityProvider<>()
                .setType(OriginKeys.SAML)
                .setOriginKey(idpZone.getSubdomain())
                .setActive(true)
                .setName("SAML IDP for Mock Tests")
                .setIdentityZoneId(spZone.getId());
        SamlIdentityProviderDefinition idpDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(getSamlMetadata(idpZone.getSubdomain(), "/saml/idp/metadata"))
                .setIdpEntityAlias(idp.getOriginKey())
                .setLinkText(idp.getName())
                .setZoneId(spZone.getId());

        if (additionalConfigCallback != null) {
            additionalConfigCallback.accept(idpDefinition);
        }

        idp.setConfig(idpDefinition);
        idp = jdbcIdentityProviderProvisioning.create(idp, spZone.getId());
    }

    private IdentityZone createZone(String zoneIdPrefix, BaseClientDetails adminClient) throws Exception {
        return MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                zoneIdPrefix + generator.generate(),
                mockMvc,
                webApplicationContext,
                adminClient, IdentityZoneHolder.getCurrentZoneId()
        ).getIdentityZone();
    }

    private static String extractAssertion(String response, boolean decode) {
        String searchFor = "name=\"SAMLResponse\" value=\"";
        return extractFormParameter(searchFor, response, decode);
    }

    private static String extractSamlRequest(String response) {
        String searchFor = "name=\"SAMLRequest\" value=\"";
        return extractFormParameter(searchFor, response, false);
    }

    private static String extractRelayState(String response) {
        String searchFor = "name=\"RelayState\" value=\"";
        return extractFormParameter(searchFor, response, false);
    }

    private static String extractFormParameter(String searchFor, String response, boolean decode) {
        int start = response.indexOf(searchFor) + searchFor.length();
        assertThat("Must find the SAML response in output\n" + response, start, greaterThan(searchFor.length()));
        int end = response.indexOf("\"/>", start);
        assertThat("Must find the SAML response in output\n" + response, end, greaterThan(start));
        String encoded = response.substring(start, end);
        if (decode) {
            return new String(Base64.getDecoder().decode(encoded));
        } else {
            return encoded;
        }
    }
}
