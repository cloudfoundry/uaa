
package org.cloudfoundry.identity.uaa.provider.ldap;

import org.apache.directory.api.ldap.model.constants.LdapSecurityConstants;
import org.apache.directory.api.ldap.model.password.PasswordUtil;

public class DynamicPasswordComparator implements org.springframework.security.crypto.password.PasswordEncoder {

    public DynamicPasswordComparator() {
    }

    public boolean comparePasswords(byte[] received, byte[] stored) {
        return PasswordUtil.compareCredentials(received, stored);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        throw new UnsupportedOperationException();
    }

    public static void main(String[] args) {
        LdapSecurityConstants test = PasswordUtil.findAlgorithm("{sha}YaE1CJ6sVhov987e77A5db7QAPg=".getBytes());
        System.out.println(test);
    }

}
