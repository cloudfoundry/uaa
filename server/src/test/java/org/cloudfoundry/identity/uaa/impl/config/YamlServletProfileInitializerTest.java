package org.cloudfoundry.identity.uaa.impl.config;

import org.junit.Test;
import java.util.Arrays;

import org.springframework.util.StringUtils;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class YamlServletProfileInitializerTest {
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
}
