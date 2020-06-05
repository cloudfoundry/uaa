package org.cloudfoundry.identity.uaa;

import com.timgroup.statsd.StatsDClient;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class UaaStatsdConfigurationSpringTest {

    @Nested
    @ExtendWith(SpringExtension.class)
    @ContextConfiguration(classes = UaaStatsdConfiguration.class)
    @TestPropertySource(properties = "statsd.enabled=true")
    class WithStatsdEnabled {
        @Test
        void statsdIsNotAvailable(@Autowired(required = false) StatsDClient statsDClient) {
            assertNotNull(statsDClient, "statsDClient must be available");
        }
    }

    @Nested
    @ExtendWith(SpringExtension.class)
    @ContextConfiguration(classes = UaaStatsdConfiguration.class)
    @TestPropertySource(properties = "statsd.enabled=baz")
    class WithStatsdExplicitlyDisabled {
        @Test
        void statsdIsNotAvailable(@Autowired(required = false) StatsDClient statsDClient) {
            assertNull(statsDClient, "statsDClient must not be available");
        }
    }

    @Nested
    @ExtendWith(SpringExtension.class)
    @ContextConfiguration(classes = UaaStatsdConfiguration.class)
    class WithStatsdDisabledByDefault {
        @Test
        void statsdIsNotAvailable(@Autowired(required = false) StatsDClient statsDClient) {
            assertNull(statsDClient, "statsDClient must not be available");
        }
    }

}