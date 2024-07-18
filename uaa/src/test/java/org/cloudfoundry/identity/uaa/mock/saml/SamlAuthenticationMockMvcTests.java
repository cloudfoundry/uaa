package org.cloudfoundry.identity.uaa.mock.saml;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.authentication.SamlResponseLoggerBinding;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.context.WebApplicationContext;
import org.xmlunit.assertj.XmlAssert;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.function.Consumer;

import static org.apache.logging.log4j.Level.DEBUG;
import static org.apache.logging.log4j.Level.WARN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.cloudfoundry.identity.uaa.authentication.SamlResponseLoggerBinding.X_VCAP_REQUEST_ID_HEADER;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.responseWithAssertions;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.serializedResponse;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2TestUtils.xmlNamespaces;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2Utils.samlDecode;
import static org.cloudfoundry.identity.uaa.provider.saml.Saml2Utils.samlDecodeAndInflate;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class SamlAuthenticationMockMvcTests {

    private RandomValueStringGenerator generator;

    private IdentityZone spZone;
    private IdentityZone idpZone;
    private String spZoneEntityId;
    private IdentityProvider<SamlIdentityProviderDefinition> idp;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    private JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;

    //    @Autowired
    //    private LoggingAuditService loggingAuditService;
    //    private InterceptingLogger testLogger;
    //    private Logger originalAuditServiceLogger;

    private static void createUser(
            JdbcScimUserProvisioning jdbcScimUserProvisioning,
            IdentityZone identityZone
    ) {
        ScimUser user = new ScimUser(null, "marissa", "first", "last");
        user.setPrimaryEmail("test@test.org");
        jdbcScimUserProvisioning.createUser(user, "secret", identityZone.getId());
    }

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @BeforeEach
    void createSamlRelationship(
            @Autowired JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning,
            @Autowired JdbcScimUserProvisioning jdbcScimUserProvisioning
    ) throws Exception {
        this.jdbcIdentityProviderProvisioning = jdbcIdentityProviderProvisioning;
        generator = new RandomValueStringGenerator();
        UaaClientDetails adminClient = new UaaClientDetails("admin", "", "", "client_credentials", "uaa.admin");
        adminClient.setClientSecret("adminsecret");

        String spZoneSubdomain = "uaa-acting-as-saml-proxy-zone-" + generator.generate();
        spZone = createZoneWithSamlSpConfig(spZoneSubdomain, adminClient, true, true, spZoneSubdomain + "-entity-id");

        String idpZoneSubdomain = "uaa-acting-as-saml-idp-zone-" + generator.generate();
        idpZone = createZoneWithSamlSpConfig(idpZoneSubdomain, adminClient, true, true, idpZoneSubdomain + "-entity-id");

        spZoneEntityId = spZone.getSubdomain() + ".cloudfoundry-saml-login";
        createUser(jdbcScimUserProvisioning, idpZone);
    }

    //    @AfterEach
    //    void putBackOriginalLogger() {
    //        loggingAuditService.setLogger(originalAuditServiceLogger);
    //    }

    @BeforeEach
    void installTestLogger() {
        //        testLogger = new InterceptingLogger();
        //        originalAuditServiceLogger = loggingAuditService.getLogger();
        //        loggingAuditService.setLogger(testLogger);
        Properties esapiProps = new Properties();
        esapiProps.put("ESAPI.Logger", "org.owasp.esapi.logging.slf4j.Slf4JLogFactory");
        esapiProps.put("ESAPI.Encoder", "org.owasp.esapi.reference.DefaultEncoder");
        esapiProps.put("Logger.LogEncodingRequired", Boolean.FALSE.toString());
        esapiProps.put("Logger.UserInfo", Boolean.TRUE.toString());
        esapiProps.put("Logger.ClientInfo", Boolean.TRUE.toString());
        esapiProps.put("Logger.ApplicationName", "uaa");
        esapiProps.put("Logger.LogApplicationName", Boolean.FALSE.toString());
        esapiProps.put("Logger.LogServerIP", Boolean.FALSE.toString());
        ESAPI.override(new DefaultSecurityConfiguration(esapiProps));
    }

    @Test
    void sendAuthnRequestToIdpRedirectBindingMode() throws Exception {
        MvcResult mvcResult = mockMvc.perform(
                        get("/uaa/saml2/authenticate/%s".formatted("testsaml-redirect-binding"))
                                .contextPath("/uaa")
                                .header(HOST, "localhost:8080")
                )
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String samlRequestUrl = mvcResult.getResponse().getRedirectedUrl();
        Map<String, String[]> parameterMap = UaaUrlUtils.getParameterMap(samlRequestUrl);
        MatcherAssert.assertThat("SAMLRequest is missing", parameterMap.get("SAMLRequest"), notNullValue());
        assertThat("SigAlg is missing", parameterMap.get("SigAlg"), notNullValue());
        assertThat("Signature is missing", parameterMap.get("Signature"), notNullValue());
        assertThat("RelayState is missing", parameterMap.get("RelayState"), notNullValue());
        assertThat(parameterMap.get("RelayState")[0], equalTo("testsaml-redirect-binding"));

        // Decode & Inflate the SAMLRequest and check the AssertionConsumerServiceURL
        String samlRequestXml = samlDecodeAndInflate(parameterMap.get("SAMLRequest")[0]);
        assertThat(samlRequestXml)
                .contains("<saml2p:AuthnRequest");

        XmlAssert xmlAssert = XmlAssert.assertThat(samlRequestXml)
                .withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/@AssertionConsumerServiceURL")
                .isEqualTo("http://localhost:8080/uaa/saml/SSO/alias/integration-saml-entity-id");
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2:Issuer")
                .isEqualTo("integration-saml-entity-id"); // matches login.entityID
    }

    @Test
    void sendAuthnRequestToIdpPostBindingMode() throws Exception {
        final String samlRequestMatch = "name=\"SAMLRequest\" value=\"";

        MvcResult mvcResult = mockMvc.perform(
                        get("/uaa/saml2/authenticate/%s".formatted("testsaml-post-binding"))
                                .contextPath("/uaa")
                                .header(HOST, "localhost:8080")
                )
                .andDo(print())
                .andExpectAll(
                        status().isOk(),
                        content().string(containsString("name=\"SAMLRequest\"")),
                        content().string(containsString("name=\"RelayState\" value=\"testsaml-post-binding\"")))
                .andReturn();

        // Decode the SAMLRequest and check the AssertionConsumerServiceURL
        String contentHtml = mvcResult.getResponse().getContentAsString();
        contentHtml = contentHtml.substring(contentHtml.indexOf(samlRequestMatch) + samlRequestMatch.length());
        contentHtml = contentHtml.substring(0, contentHtml.indexOf("\""));
        String samlRequestXml = new String(samlDecode(contentHtml), StandardCharsets.UTF_8);
        assertThat(samlRequestXml).contains("<saml2p:AuthnRequest");

        XmlAssert xmlAssert = XmlAssert.assertThat(samlRequestXml)
                .withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/@AssertionConsumerServiceURL")
                .isEqualTo("http://localhost:8080/uaa/saml/SSO/alias/integration-saml-entity-id");
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2:Issuer")
                .isEqualTo("integration-saml-entity-id"); // matches login.entityID
    }

    @Test
    void sendAuthnRequestFromNonDefaultZoneToIdpRedirectBindingMode() throws Exception {
        // create IDP in non-default zone
        createMockSamlIdpInSpZone("classpath:test-saml-idp-metadata-redirect-binding.xml", "testsaml-redirect-binding");

        // trigger saml login in the non-default zone
        MvcResult mvcResult = mockMvc.perform(
                        get("/uaa/saml2/authenticate/%s".formatted("testsaml-redirect-binding"))
                                .contextPath("/uaa")
                                .header(HOST, "%s.localhost:8080".formatted(spZone.getSubdomain()))
                )
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String samlRequestUrl = mvcResult.getResponse().getRedirectedUrl();
        Map<String, String[]> parameterMap = UaaUrlUtils.getParameterMap(samlRequestUrl);
        MatcherAssert.assertThat("SAMLRequest is missing", parameterMap.get("SAMLRequest"), notNullValue());
        assertThat("SigAlg is missing", parameterMap.get("SigAlg"), notNullValue());
        assertThat("Signature is missing", parameterMap.get("Signature"), notNullValue());
        assertThat("RelayState is missing", parameterMap.get("RelayState"), notNullValue());
        assertThat(parameterMap.get("RelayState")[0], equalTo("testsaml-redirect-binding"));

        // Decode & Inflate the SAMLRequest and check the AssertionConsumerServiceURL
        String samlRequestXml = samlDecodeAndInflate(parameterMap.get("SAMLRequest")[0]);
        XmlAssert xmlAssert = XmlAssert.assertThat(samlRequestXml).withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/@AssertionConsumerServiceURL")
                .isEqualTo("http://%1$s.localhost:8080/uaa/saml/SSO/alias/%1$s.integration-saml-entity-id".formatted(spZone.getSubdomain()));
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2:Issuer")
                .isEqualTo(spZone.getConfig().getSamlConfig().getEntityID()); // should match zone config's samlConfig.entityID
    }

    @Test
    void sendAuthnRequestFromNonDefaultZoneToIdpRedirectBindingMode_ZoneConfigSamlEntityIDNotSet() throws Exception {
        // create a new zone without zone saml entity ID not set
        UaaClientDetails adminClient = new UaaClientDetails("admin", "", "", "client_credentials", "uaa.admin");
        adminClient.setClientSecret("adminsecret");
        String spZoneSubdomain = "uaa-acting-as-saml-proxy-zone-" + generator.generate();
        spZone = createZoneWithSamlSpConfig(spZoneSubdomain, adminClient, true, true, null);

        // create IDP in non-default zone
        createMockSamlIdpInSpZone("classpath:test-saml-idp-metadata-redirect-binding.xml", "testsaml-redirect-binding");

        // trigger saml login in the non-default zone
        MvcResult mvcResult = mockMvc.perform(
                        get("/uaa/saml2/authenticate/%s".formatted("testsaml-redirect-binding"))
                                .contextPath("/uaa")
                                .header(HOST, "%s.localhost:8080".formatted(spZone.getSubdomain()))
                )
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String samlRequestUrl = mvcResult.getResponse().getRedirectedUrl();
        Map<String, String[]> parameterMap = UaaUrlUtils.getParameterMap(samlRequestUrl);
        MatcherAssert.assertThat("SAMLRequest is missing", parameterMap.get("SAMLRequest"), notNullValue());
        assertThat("SigAlg is missing", parameterMap.get("SigAlg"), notNullValue());
        assertThat("Signature is missing", parameterMap.get("Signature"), notNullValue());
        assertThat("RelayState is missing", parameterMap.get("RelayState"), notNullValue());
        assertThat(parameterMap.get("RelayState")[0], equalTo("testsaml-redirect-binding"));

        // Decode & Inflate the SAMLRequest and check the AssertionConsumerServiceURL
        String samlRequestXml = samlDecodeAndInflate(parameterMap.get("SAMLRequest")[0]);
        XmlAssert xmlAssert = XmlAssert.assertThat(samlRequestXml).withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/@AssertionConsumerServiceURL")
                .isEqualTo("http://%1$s.localhost:8080/uaa/saml/SSO/alias/%1$s.integration-saml-entity-id".formatted(spZone.getSubdomain()));
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2:Issuer")
                .isEqualTo("%s.%s".formatted(spZone.getSubdomain(), "integration-saml-entity-id")); // should match zone config's samlConfig.entityID; if not set, fail over to zone-subdomain.uaa-wide-saml-entity-id
    }

    @Test
    void sendAuthnRequestFromNonDefaultZoneToIdpPostBindingMode() throws Exception {
        // create IDP in non-default zone
        createMockSamlIdpInSpZone("classpath:test-saml-idp-metadata-post-binding.xml", "testsaml-post-binding");

        final String samlRequestMatch = "name=\"SAMLRequest\" value=\"";

        MvcResult mvcResult = mockMvc.perform(
                        get("/uaa/saml2/authenticate/%s".formatted("testsaml-post-binding"))
                                .contextPath("/uaa")
                                .header(HOST, "%s.localhost:8080".formatted(spZone.getSubdomain()))
                )
                .andDo(print())
                .andExpectAll(
                        status().isOk(),
                        content().string(containsString("name=\"SAMLRequest\"")),
                        content().string(containsString("name=\"RelayState\" value=\"testsaml-post-binding\"")))
                .andReturn();

        // Decode the SAMLRequest and check the AssertionConsumerServiceURL
        String contentHtml = mvcResult.getResponse().getContentAsString();
        contentHtml = contentHtml.substring(contentHtml.indexOf(samlRequestMatch) + samlRequestMatch.length());
        contentHtml = contentHtml.substring(0, contentHtml.indexOf("\""));
        String samlRequestXml = new String(samlDecode(contentHtml), StandardCharsets.UTF_8);
        assertThat(samlRequestXml).contains("<saml2p:AuthnRequest");

        XmlAssert xmlAssert = XmlAssert.assertThat(samlRequestXml)
                .withNamespaceContext(xmlNamespaces());
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/@AssertionConsumerServiceURL")
                .isEqualTo("http://%1$s.localhost:8080/uaa/saml/SSO/alias/%1$s.integration-saml-entity-id".formatted(spZone.getSubdomain()));
        xmlAssert.valueByXPath("//saml2p:AuthnRequest/saml2:Issuer")
                .isEqualTo(spZone.getConfig().getSamlConfig().getEntityID()); // should match zone config's samlConfig.entityID
    }

    @Test
    void receiveAuthnResponseFromIdpToLegacyAliasUrl() throws Exception {

        String encodedSamlResponse = serializedResponse(responseWithAssertions());
        mockMvc.perform(
                        post("/uaa/saml/SSO/alias/%s".formatted("cloudfoundry-saml-login"))
                                .contextPath("/uaa")
                                .header(HOST, "localhost:8080")
                                .param("SAMLResponse", encodedSamlResponse)
                                .param("RelayState", "testsaml-post-binding")
                )
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                // expect redirect to the Uaa Home Page: /uaa/
                .andExpect(redirectedUrl("/uaa/"))
                .andReturn();
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

    private String getSamlMetadata(String subdomain, String url) throws Exception {
        return mockMvc.perform(
                        get(url)
                                .header("Host", subdomain + ".localhost")
                )
                .andReturn().getResponse().getContentAsString();
    }

    void createIdp() throws Exception {
        createIdp(null);
    }

    private void createIdp(Consumer<SamlIdentityProviderDefinition> additionalConfigCallback) throws Exception {
        idp = new IdentityProvider<SamlIdentityProviderDefinition>()
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

    private void createMockSamlIdpInSpZone(String metadataLocation, String idpOriginKey) {
        idp = new IdentityProvider<SamlIdentityProviderDefinition>()
                .setType(OriginKeys.SAML)
                .setOriginKey(idpOriginKey)
                .setActive(true)
                .setName("SAML IDP for Mock Tests")
                .setIdentityZoneId(spZone.getId());
        SamlIdentityProviderDefinition idpDefinition = new SamlIdentityProviderDefinition()
                .setMetaDataLocation(metadataLocation)
                .setIdpEntityAlias(idp.getOriginKey())
                .setLinkText(idp.getName())
                .setZoneId(spZone.getId());

        idp.setConfig(idpDefinition);
        idp = jdbcIdentityProviderProvisioning.create(idp, spZone.getId());
    }

    private IdentityZone createZone(String zoneIdPrefix, UaaClientDetails adminClient) throws Exception {
        return MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                zoneIdPrefix + generator.generate(),
                mockMvc,
                webApplicationContext,
                adminClient, IdentityZoneHolder.getCurrentZoneId()
        ).getIdentityZone();
    }

    private IdentityZone createZoneWithSamlSpConfig(String zoneSubdomain, UaaClientDetails adminClient, Boolean samlRequestSigned, Boolean samlWantAssertionSigned, String samlZoneEntityID) throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone(zoneSubdomain, zoneSubdomain);
        identityZone.getConfig().getSamlConfig().setRequestSigned(samlRequestSigned);
        identityZone.getConfig().getSamlConfig().setWantAssertionSigned(samlWantAssertionSigned);
        identityZone.getConfig().getSamlConfig().setEntityID(samlZoneEntityID);
        return MockMvcUtils.createOtherIdentityZoneAndReturnResult(mockMvc, webApplicationContext, adminClient, identityZone, true, IdentityZoneHolder.getCurrentZoneId()).getIdentityZone();
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
            if (!(actual instanceof LogEvent logEvent)) {
                return false;
            }

            return expectedLevel.equals(logEvent.getLevel())
                    && expectedMessage.equals(logEvent.getMessage().getFormattedMessage());
        }

        @Override
        public void describeTo(Description description) {
            description.appendText(String.format("LogEvent with level of {%s} and message of {%s}", this.expectedLevel, this.expectedMessage));
        }
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
        @Disabled("SAML test fails")
        void malformedSamlRequestLogsQueryStringAndContentMetadata() throws Exception {
            postSamlResponse(null, "?bogus=query", "someKey=someVal&otherKey=otherVal&emptyKey=", "vcap_request_id_abc123");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (bogus/5) (emptyKey/0) (SAMLResponse/0) (someKey/7) (otherKey/8), Content-type: application/x-www-form-urlencoded, Request-size: 43, X-Vcap-Request-Id: vcap_request_id_abc123");
        }

        @Test
        @Disabled("SAML test fails")
        void malformedSamlRequestWithNoQueryStringAndNoContentMetadata() throws Exception {
            postSamlResponse(null, "", "", "");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (SAMLResponse/0), Content-type: application/x-www-form-urlencoded, Request-size: 0, X-Vcap-Request-Id: ");
        }

        @Test
        @Disabled("SAML test fails")
        void malformedSamlRequestWithRepeatedParams() throws Exception {
            postSamlResponse(null, "?foo=a&foo=ab&foo=aaabbbccc", "", "");

            assertThatMessageWasLogged(logEvents, WARN, "Malformed SAML response. More details at log level DEBUG.");
            assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (foo/1) (foo/2) (foo/9) (SAMLResponse/0), Content-type: application/x-www-form-urlencoded, Request-size: 0, X-Vcap-Request-Id: ");
        }

        private void assertThatMessageWasLogged(
                final List<LogEvent> logEvents,
                final Level expectedLevel,
                final String expectedMessage
        ) {
            assertThat(logEvents).extracting(LogEvent::getLevel, LogEvent::getMessage)
                    .contains(tuple(expectedLevel, expectedMessage));
        }
    }
}
