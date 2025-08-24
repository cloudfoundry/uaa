package org.cloudfoundry.identity.uaa.web.beans;

import org.cloudfoundry.identity.uaa.UaaProperties;
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
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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

        assertThat(new UaaMemorySessionConfig.MemoryConfigured().matches(mockConditionContext, null)).isFalse();
        assertThat(new UaaJdbcSessionConfig.DatabaseConfigured().matches(mockConditionContext, null)).isTrue();
    }

    @Test
    void whenMemoryIsConfigured() {
        when(mockEnvironment.getProperty("servlet.session-store", "memory")).thenReturn("memory");

        assertThat(new UaaMemorySessionConfig.MemoryConfigured().matches(mockConditionContext, null)).isTrue();
        assertThat(new UaaJdbcSessionConfig.DatabaseConfigured().matches(mockConditionContext, null)).isFalse();
    }

    @Test
    void whenFoobarIsConfigured() {
        when(mockEnvironment.getProperty("servlet.session-store", "memory")).thenReturn("foobar");

        assertThatThrownBy(() -> new UaaMemorySessionConfig.MemoryConfigured().matches(mockConditionContext, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("foobar is not a valid argument for servlet.session-store. Please choose memory or database.");
        assertThatThrownBy(() -> new UaaJdbcSessionConfig.DatabaseConfigured().matches(mockConditionContext, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("foobar is not a valid argument for servlet.session-store. Please choose memory or database.");
    }

    @Test
    void whenCookieSeralizeDefault() {
        when(mockEnvironment.getProperty("servlet.session-store", "memory")).thenReturn("database");
        assertThat(new UaaJdbcSessionConfig.DatabaseConfigured().matches(mockConditionContext, null)).isTrue();
        assertThat(runCookieTest(true)).isEmpty();
    }

    @Test
    void whenCookieSeralizeNoDefault() {
        when(mockEnvironment.getProperty("servlet.session-store", "memory")).thenReturn("database");
        assertThat(new UaaJdbcSessionConfig.DatabaseConfigured().matches(mockConditionContext, null)).isTrue();
        assertThat(runCookieTest(false)).hasSize(1);
    }

    private static List<String> runCookieTest(boolean defaults) {
        String sessionId = UUID.randomUUID().toString();
        String sessionName = "JSESSIONID";
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest("GET", "/uaa/login");
        MockHttpServletResponse mockHttpServletResponse = new MockHttpServletResponse();
        UaaSessionConfig config = new UaaJdbcSessionConfig();
        var defaultProps = new UaaProperties.Servlet(new UaaProperties.SessionCookie(true, -1), 0, Collections.emptyList());
        var customProps = new UaaProperties.Servlet(new UaaProperties.SessionCookie(false, 1), 0, Collections.emptyList());
        CookieSerializer cookieSerializer = config.uaaCookieSerializer(defaults ? defaultProps : customProps);
        mockHttpServletRequest.setCookies(new Cookie(sessionName, sessionId));
        List<String> cookies = cookieSerializer.readCookieValues(mockHttpServletRequest);
        for (String value : cookies) {
            cookieSerializer.writeCookieValue(new CookieSerializer.CookieValue(mockHttpServletRequest, mockHttpServletResponse, value));
        }
        return cookies;
    }
}