package org.cloudfoundry.identity.uaa.web.beans;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.equalTo;
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
}