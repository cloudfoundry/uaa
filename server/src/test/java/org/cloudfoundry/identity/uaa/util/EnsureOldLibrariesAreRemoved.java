package org.cloudfoundry.identity.uaa.util;

import org.junit.Test;
import org.springframework.util.ClassUtils;

import static org.junit.Assert.fail;

public class EnsureOldLibrariesAreRemoved {

    @Test
    public void oldJacksonParserShouldBeGone() {
        if (ClassUtils.isPresent("org.codehaus.jackson.map.ObjectMapper", null)) {
            fail("org.codehaus.jackson.map.ObjectMapper should not be in the class path!");
        }
    }

    @Test
    public void szxcvbnShouldBeGone() {
        if (ClassUtils.isPresent("szxcvbn.ZxcvbnHelper", null)) {
            fail("szxcvbn.ZxcvbnHelper");
        }
    }

}
