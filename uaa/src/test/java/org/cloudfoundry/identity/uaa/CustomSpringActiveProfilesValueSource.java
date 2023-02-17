package org.cloudfoundry.identity.uaa;

import org.springframework.test.annotation.ProfileValueSource;
import org.springframework.test.annotation.SystemProfileValueSource;
import org.springframework.util.Assert;

public class CustomSpringActiveProfilesValueSource implements ProfileValueSource {

    private final SystemProfileValueSource systemProfileValueSource;

    public CustomSpringActiveProfilesValueSource() {
        systemProfileValueSource = SystemProfileValueSource.getInstance();
    }

    @Override
    public String get(String key) {
        Assert.hasText(key, "'key' must not be empty");
        if (key.equals("spring.profiles.active")) {
            String springActiveProfile = systemProfileValueSource.get(key);
            if (springActiveProfile != null && springActiveProfile.toLowerCase().contains("nurego")) {
                return "nurego";
            } else {
                return springActiveProfile;
            }
        } else {
            return systemProfileValueSource.get(key);
        }
    }
}