package org.cloudfoundry.identity.uaa.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordEncoderFactory {

    private static Logger logger = LoggerFactory.getLogger(PasswordEncoderFactory.class);

    public PasswordEncoder get() {
        try {
            return createFakePasswordEncoder();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            return createRealPasswordEncoder();
        }
    }

    PasswordEncoder createFakePasswordEncoder() throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        // FakePasswordEncoder is a test class, and will not exist in a production or development UAA
        String testPasswdEncoderclassName = "org.cloudfoundry.identity.uaa.util.FakePasswordEncoder";
        Class klass = Class.forName(testPasswdEncoderclassName);
        PasswordEncoder passwordEncoder = (PasswordEncoder) klass.newInstance();
        logger.error("Created instance of FakePasswordEncoder. This should only happen in unit tests! This is a serious error in production!");
        return passwordEncoder;
    }

    PasswordEncoder createRealPasswordEncoder() {
        // This Spring library class should always be used in production
        logger.info("Created instance of BCryptPasswordEncoder");
        return new BCryptPasswordEncoder();
    }

}
