
package org.cloudfoundry.identity.uaa.test;

import org.springframework.test.annotation.ProfileValueSource;
import org.springframework.util.Assert;

/**
 * Simple implementation of {@link ProfileValueSource} that returns an empty
 * String instead of a null value if the
 * property is missing, and otherwise gets it from System properties.
 * 
 * @author Dave Syer
 * 
 */
public class NullSafeSystemProfileValueSource implements ProfileValueSource {

    @Override
    public String get(String key) {
        Assert.hasText(key, "'key' must not be empty");
        return System.getProperty(key, "");
    }

}
