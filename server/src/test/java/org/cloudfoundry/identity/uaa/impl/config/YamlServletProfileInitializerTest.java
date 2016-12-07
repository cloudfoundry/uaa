package org.cloudfoundry.identity.uaa.impl.config;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockServletContext;
import org.springframework.util.StringUtils;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThat;

public class YamlServletProfileInitializerTest {

    private static String systemConfiguredProfiles;
    private YamlServletProfileInitializer initializer;
    private MockEnvironment environment;
    private MockServletContext context;

    @BeforeClass
    public static void saveProfiles() {
        systemConfiguredProfiles = System.getProperty("spring.profiles.active");
    }

    @AfterClass
    public static void restoreProfiles() {
        if (systemConfiguredProfiles != null) {
            System.setProperty("spring.profiles.active", systemConfiguredProfiles);
        } else {
            System.clearProperty("spring.profiles.active");
        }
    }

    @Before
    public void setup() {
        initializer = new YamlServletProfileInitializer();
        environment = new MockEnvironment();
        context = new MockServletContext();
    }

    @Test
    public void tokenizeToStringArray_RemovesSpaces() throws Exception {
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
    public void if_no_profiles_are_set_use_hsqldb() {
        System.clearProperty("spring.profiles.active");
        initializer.applySpringProfiles(environment, context);
        assertArrayEquals(new String[] {"hsqldb"}, environment.getActiveProfiles());
    }

    @Test
    public void if_profiles_are_set_use_them() {
        System.setProperty("spring.profiles.active", "hsqldb,default");
        initializer.applySpringProfiles(environment, context);
        assertArrayEquals(new String[] {"hsqldb", "default"}, environment.getActiveProfiles());
    }

    @Test
    public void default_profile_unset() {
        System.setProperty("spring.profiles.active", "hsqldb");
        initializer.applySpringProfiles(environment, context);
        assertArrayEquals(new String[] {"hsqldb"}, environment.getActiveProfiles());
        assertArrayEquals(new String[0], environment.getDefaultProfiles());
    }

    @Test
    public void yaml_configured_profiles_are_used() {
        System.setProperty("spring.profiles.active", "hsqldb,default");
        environment.setProperty("spring_profiles", "mysql,default");
        initializer.applySpringProfiles(environment, context);
        assertArrayEquals(new String[] {"mysql", "default"}, environment.getActiveProfiles());
    }
}
