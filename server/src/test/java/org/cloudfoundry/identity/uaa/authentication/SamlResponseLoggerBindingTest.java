package org.cloudfoundry.identity.uaa.authentication;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.ws.transport.InputStreamInTransportAdapter;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import java.util.HashMap;
import java.util.Map;

import static org.apache.logging.log4j.Level.DEBUG;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SamlResponseLoggerBindingTest {

    private SamlResponseLoggerBinding samlResponseLoggerBinding;

    private Level originalLevel;

    @BeforeEach
    void setUp() {
        samlResponseLoggerBinding = new SamlResponseLoggerBinding();

        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        originalLevel = context.getRootLogger().getLevel();
    }

    @AfterEach
    void tearDown() {
        Configurator.setRootLevel(originalLevel);
    }

    @Test
    void xVcapRequestId() {
        assertThat(SamlResponseLoggerBinding.X_VCAP_REQUEST_ID_HEADER, is("X-Vcap-Request-Id"));
    }

    @Test
    void doesNotFailWithSomethingOtherThanHttpServletRequestAdapter() {
        InputStreamInTransportAdapter inputStreamInTransportAdapter = new InputStreamInTransportAdapter(null);

        assertDoesNotThrow(() -> samlResponseLoggerBinding.supports(inputStreamInTransportAdapter));
    }

    @Test
    void doesNotFailWithNullServletRequest() {
        HttpServletRequestAdapter httpServletRequestAdapter = new HttpServletRequestAdapter(null);

        Configurator.setRootLevel(DEBUG);

        assertDoesNotThrow(() -> samlResponseLoggerBinding.supports(httpServletRequestAdapter));
    }

    @Test
    void doesNotFailWithNullParameterMap() {
        HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);
        when(mockHttpServletRequest.getParameterMap()).thenReturn(null);
        HttpServletRequestAdapter httpServletRequestAdapter = new HttpServletRequestAdapter(mockHttpServletRequest);

        Configurator.setRootLevel(DEBUG);

        assertDoesNotThrow(() -> samlResponseLoggerBinding.supports(httpServletRequestAdapter));
    }

    @Test
    void doesNotFailWithNullParameter() {
        HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);
        Map<String, String[]> parameters = new HashMap<>();
        parameters.put(null, null);
        parameters.put("key1", null);
        parameters.put("key2", new String[]{null});
        parameters.put("key3", new String[]{"value", null});
        when(mockHttpServletRequest.getParameterMap()).thenReturn(parameters);
        HttpServletRequestAdapter httpServletRequestAdapter = new HttpServletRequestAdapter(mockHttpServletRequest);

        Configurator.setRootLevel(DEBUG);

        assertDoesNotThrow(() -> samlResponseLoggerBinding.supports(httpServletRequestAdapter));
    }
}
