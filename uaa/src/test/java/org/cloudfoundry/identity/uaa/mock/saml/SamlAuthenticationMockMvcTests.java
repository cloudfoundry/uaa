package org.cloudfoundry.identity.uaa.mock.saml;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.authentication.SamlResponseLoggerBinding;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.InterceptingLogger;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.Assert;
import org.junit.jupiter.api.*;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.reference.DefaultSecurityConfiguration;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.WebApplicationContext;
import org.w3c.dom.Node;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.function.Consumer;

import static org.apache.logging.log4j.Level.DEBUG;
import static org.apache.logging.log4j.Level.WARN;
import static org.cloudfoundry.identity.uaa.authentication.SamlResponseLoggerBinding.X_VCAP_REQUEST_ID_HEADER;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertEquals;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.HOST;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

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

    @Autowired
    private LoggingAuditService loggingAuditService;
    private InterceptingLogger testLogger;
    private Logger originalAuditServiceLogger;

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
        spZone = createZone("uaa-acting-as-saml-proxy-zone-", adminClient);
        idpZone = createZone("uaa-acting-as-saml-idp-zone-", adminClient);
        spZoneEntityId = spZone.getSubdomain() + ".cloudfoundry-saml-login";
        createUser(jdbcScimUserProvisioning, idpZone);
    }

    @BeforeEach
    void installTestLogger() {
        testLogger = new InterceptingLogger();
        originalAuditServiceLogger = loggingAuditService.getLogger();
        loggingAuditService.setLogger(testLogger);
        Properties esapiProps = new Properties();
        esapiProps.put("ESAPI.Logger", "org.owasp.esapi.logging.slf4j.Slf4JLogFactory");
        esapiProps.put("ESAPI.Encoder", "org.owasp.esapi.reference.DefaultEncoder");
        esapiProps.put("Logger.LogEncodingRequired", Boolean.FALSE.toString());
        esapiProps.put("Logger.UserInfo", Boolean.TRUE.toString());
        esapiProps.put("Logger.ClientInfo", Boolean.TRUE.toString());
        esapiProps.put("Logger.ApplicationName", "uaa");
        esapiProps.put("Logger.LogApplicationName", Boolean.FALSE.toString());
        esapiProps.put("Logger.LogServerIP", Boolean.FALSE.toString());
        ESAPI.override( new DefaultSecurityConfiguration(esapiProps));
    }

    @AfterEach
    void putBackOriginalLogger() {
        loggingAuditService.setLogger(originalAuditServiceLogger);
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

    private IdentityZone createZone(String zoneIdPrefix, UaaClientDetails adminClient) throws Exception {
        return MockMvcUtils.createOtherIdentityZoneAndReturnResult(
                zoneIdPrefix + generator.generate(),
                mockMvc,
                webApplicationContext,
                adminClient, IdentityZoneHolder.getCurrentZoneId()
        ).getIdentityZone();
    }
}
