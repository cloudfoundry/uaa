package org.cloudfoundry.identity.uaa.web.beans;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.session.web.http.CookieSerializer;

import jakarta.servlet.http.Cookie;
import java.util.List;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(MockitoExtension.class)
class UaaSessionConfigTest {

    @Mock
    private ConditionContext mockConditionContext;

    @Mock
    private Environment mockEnvironment;

    @BeforeEach
    void setUp() {
        when(mockConditionContext.getEnvironment()).thenReturn(mockEnvironment);
    }

    @Test
    void whenDatabaseIsConfigured() {
        when(mockEnvironment.getProperty("servlet.session-store", "memory")).thenReturn("database");

        assertFalse(new UaaMemorySessionConfig.MemoryConfigured().matches(mockConditionContext, null));
        assertTrue(new UaaJdbcSessionConfig.DatabaseConfigured().matches(mockConditionContext, null));
    }

    @Test
    void whenMemoryIsConfigured() {
        when(mockEnvironment.getProperty("servlet.session-store", "memory")).thenReturn("memory");

        assertTrue(new UaaMemorySessionConfig.MemoryConfigured().matches(mockConditionContext, null));
        assertFalse(new UaaJdbcSessionConfig.DatabaseConfigured().matches(mockConditionContext, null));
    }

    @Test
    void whenFoobarIsConfigured() {
        when(mockEnvironment.getProperty("servlet.session-store", "memory")).thenReturn("foobar");

        assertThrowsWithMessageThat(
                IllegalArgumentException.class,
                () -> new UaaMemorySessionConfig.MemoryConfigured().matches(mockConditionContext, null),
                equalTo("foobar is not a valid argument for servlet.session-store. Please choose memory or database."));
        assertThrowsWithMessageThat(
                IllegalArgumentException.class,
                () -> new UaaJdbcSessionConfig.DatabaseConfigured().matches(mockConditionContext, null),
                equalTo("foobar is not a valid argument for servlet.session-store. Please choose memory or database."));
    }

    @Test
    void whenCookieSeralizeDefault() {
        when(mockEnvironment.getProperty("servlet.session-store", "memory")).thenReturn("database");
        assertTrue(new UaaJdbcSessionConfig.DatabaseConfigured().matches(mockConditionContext, null));
        assertEquals(0, runCookieTest(true).size());
    }

    @Test
    void whenCookieSeralizeNoDefault() {
        when(mockEnvironment.getProperty("servlet.session-store", "memory")).thenReturn("database");
        assertTrue(new UaaJdbcSessionConfig.DatabaseConfigured().matches(mockConditionContext, null));
        assertEquals(1, runCookieTest(false).size());
    }

    private static List<String> runCookieTest(boolean defaults) {
        String sessionId = UUID.randomUUID().toString();
        String sessionName = "JSESSIONID";
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest("GET", "/uaa/login");
        MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();
        UaaSessionConfig config = new UaaJdbcSessionConfig();
        CookieSerializer cookieSerializer = config.uaaCookieSerializer(defaults ? -1 : 1, defaults ? true : false);
        mockHttpServletRequest.setCookies(new Cookie(sessionName, sessionId));
        List<String> cookies = cookieSerializer.readCookieValues(mockHttpServletRequest);
        for (String value : cookies) {
            cookieSerializer.writeCookieValue(new CookieSerializer.CookieValue(mockHttpServletRequest, mockHttpServletResponse, value));
        }
        return cookies;
    }
}