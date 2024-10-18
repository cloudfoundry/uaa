package org.cloudfoundry.identity.uaa.authentication;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.apache.logging.log4j.Level.DEBUG;
import static org.apache.logging.log4j.Level.INFO;
import static org.apache.logging.log4j.Level.WARN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.authentication.MalformedSamlResponseLogger.X_VCAP_REQUEST_ID_HEADER;

class MalformedSamlResponseLoggerTest {

    private static final String MALFORMED_MESSAGE = "Malformed SAML response. More details at log level DEBUG.";

    private MalformedSamlResponseLogger malformedSamlResponseLogger;

    private static final String LOGGER_NAME = "org.cloudfoundry.identity.uaa.authentication.SamlResponseLoggerBinding";
    private static Level originalLevel;
    private static List<LogEvent> logEvents;
    private static AbstractAppender appender;

    MockHttpServletRequest mockHttpServletRequest;

    @BeforeAll
    static void setupLogger() {
        logEvents = new ArrayList<>();
        appender = new AbstractAppender("", null, null, true, null) {
            @Override
            public void append(LogEvent event) {
                if (LOGGER_NAME.equals(event.getLoggerName())) {
                    logEvents.add(event);
                }
            }
        };
        appender.start();

        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        originalLevel = context.getRootLogger().getLevel();
        Configurator.setRootLevel(DEBUG);
        context.getRootLogger().addAppender(appender);
    }

    @BeforeEach
    void setUp() {
        logEvents.clear();
        mockHttpServletRequest = new MockHttpServletRequest("GET", "/test");
        mockHttpServletRequest.setContentType("application/json");
        malformedSamlResponseLogger = new MalformedSamlResponseLogger();
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        originalLevel = context.getRootLogger().getLevel();
    }

    @AfterAll
    static void removeAppender() {
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        context.getRootLogger().removeAppender(appender);
        Configurator.setRootLevel(originalLevel);
    }

    @Test
    void doesNotFailWithNullParameterMap() {
        Configurator.setRootLevel(DEBUG);
        malformedSamlResponseLogger.logMalformedResponse(mockHttpServletRequest);
        assertThat(logEvents).hasSize(2);
        assertThatMessageWasLogged(logEvents, WARN, MALFORMED_MESSAGE);
    }

    @Test
    void doesNotFailWithNullParameter() {
        mockHttpServletRequest.addHeader(X_VCAP_REQUEST_ID_HEADER, "1234");
        mockHttpServletRequest.setParameter("", new String[]{null});
        mockHttpServletRequest.setParameter("key1", new String[]{null});
        mockHttpServletRequest.setParameter("key2", null, "");
        mockHttpServletRequest.setParameter("key3", "value", null);

        Configurator.setRootLevel(DEBUG);
        malformedSamlResponseLogger.logMalformedResponse(mockHttpServletRequest);
        assertThat(logEvents).hasSize(2);
        assertThatMessageWasLogged(logEvents, WARN, MALFORMED_MESSAGE);
        assertThatMessageWasLogged(logEvents, DEBUG, "Method: GET, Params (name/size): (/0) (key1/0) (key2/0) (key2/0) (key3/5) (key3/0), Content-type: application/json, Request-size: -1, X-Vcap-Request-Id: 1234");
    }

    @Test
    void logsDetailsAtDebugLevel() {
        mockHttpServletRequest.setMethod("POST");
        mockHttpServletRequest.addHeader(X_VCAP_REQUEST_ID_HEADER, "12345");
        mockHttpServletRequest.setParameter("key1", new String[]{"value"});
        mockHttpServletRequest.setParameter("key2", new String[]{"value2"});
        mockHttpServletRequest.setContentType("application/xml");
        mockHttpServletRequest.setContent("data".getBytes(StandardCharsets.UTF_8));

        Configurator.setRootLevel(DEBUG);
        malformedSamlResponseLogger.logMalformedResponse(mockHttpServletRequest);
        assertThat(logEvents).hasSize(2);
        assertThatMessageWasLogged(logEvents, WARN, MALFORMED_MESSAGE);
        assertThatMessageWasLogged(logEvents, DEBUG, "Method: POST, Params (name/size): (key1/5) (key2/6), Content-type: application/xml, Request-size: 4, X-Vcap-Request-Id: 12345");
    }

    @Test
    void noDetailsAtInfoLevel() {
        mockHttpServletRequest.setParameter("key1", new String[]{null});
        Configurator.setRootLevel(INFO);
        malformedSamlResponseLogger.logMalformedResponse(mockHttpServletRequest);
        assertThat(logEvents).hasSize(1);
        assertThatMessageWasLogged(logEvents, WARN, MALFORMED_MESSAGE);
    }

    private void assertThatMessageWasLogged(
            final List<LogEvent> logEvents,
            final Level expectedLevel,
            final String expectedMessage) {

        assertThat(logEvents).filteredOn(l -> l.getLevel().equals(expectedLevel))
                .first()
                .returns(expectedMessage, l -> l.getMessage().getFormattedMessage());
    }
}
