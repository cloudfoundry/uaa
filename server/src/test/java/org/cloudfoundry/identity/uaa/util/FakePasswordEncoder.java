package org.cloudfoundry.identity.uaa.util;

import org.springframework.security.crypto.password.PasswordEncoder;

public class FakePasswordEncoder implements PasswordEncoder {

    // In production we should always use BCryptPasswordEncoder from Spring Security.
    //
    // However, in test we found that BCryptPasswordEncoder#encode() accounted for 37%
    // of the total runtime of the unit test suite, so to speed up the unit tests we
    // provide this fast alternative implementation.
    //
    // In test, this class is loaded by PasswordEncoderFactory using reflection.
    // If you move or rename this class, please be sure to update the factory.

    private static final String PREFIX = "fakeEncodedPassword:plaintext=";

    @Override
    public String encode(CharSequence rawPassword) {
        System.out.println("FakePasswordEncoder");
        return PREFIX + rawPassword;
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        System.out.println("FakePasswordEncoder");
        return encodedPassword.equals(PREFIX + rawPassword);
    }
}
