package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockServletContext;
import org.springframework.util.StringUtils;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThat;

@ExtendWith(PollutionPreventionExtension.class)
class YamlServletProfileInitializerTest {

    private static String systemConfiguredProfiles;
    private YamlServletProfileInitializer initializer;
    private MockEnvironment environment;
    private MockServletContext context;

    @BeforeAll
    static void saveProfiles() {
        systemConfiguredProfiles = System.getProperty("spring.profiles.active");
    }

    @AfterAll
    static void restoreProfiles() {
        if (systemConfiguredProfiles != null) {
            System.setProperty("spring.profiles.active", systemConfiguredProfiles);
        } else {
            System.clearProperty("spring.profiles.active");
        }
    }

    @BeforeEach
    void setup() {
        initializer = new YamlServletProfileInitializer();
        environment = new MockEnvironment();
        context = new MockServletContext();
    }

    @Test
    void tokenizeToStringArray_RemovesSpaces() {
        String profileString = "    database    ,  ldap ";
        String[] profiles = StringUtils.tokenizeToStringArray(profileString, ",", true, true);
        assertThat(profiles.length, is(2));
        assertThat(profiles[0], is("database"));
        assertThat(profiles[1], is("ldap"));
        // And show what's wrong with commaDelimitedListToStringArray
        profiles = StringUtils.commaDelimitedListToStringArray(profileString);
        assertThat(profiles.length, is(2));
        assertThat(profiles[0], is("    database    "));
        assertThat(profiles[1], is("  ldap "));
    }

    @Test
    void ifNoProfilesAreSetUseHsqldb() {
        System.clearProperty("spring.profiles.active");
        initializer.applySpringProfiles(environment, context);
        assertArrayEquals(new String[]{"hsqldb"}, environment.getActiveProfiles());
    }

    @Test
    void ifProfilesAreSetUseThem() {
        System.setProperty("spring.profiles.active", "hsqldb,default");
        initializer.applySpringProfiles(environment, context);
        assertArrayEquals(new String[]{"hsqldb", "default"}, environment.getActiveProfiles());
    }

    @Test
    void defaultProfileUnset() {
        System.setProperty("spring.profiles.active", "hsqldb");
        initializer.applySpringProfiles(environment, context);
        assertArrayEquals(new String[]{"hsqldb"}, environment.getActiveProfiles());
        assertArrayEquals(new String[0], environment.getDefaultProfiles());
    }

    @Test
    void yamlConfiguredProfilesAreUsed() {
        System.setProperty("spring.profiles.active", "hsqldb,default");
        environment.setProperty("spring_profiles", "mysql,default");
        initializer.applySpringProfiles(environment, context);
        assertArrayEquals(new String[]{"mysql", "default"}, environment.getActiveProfiles());
    }
}
