package org.cloudfoundry.identity.uaa.authentication.manager.builders;

import org.cloudfoundry.identity.uaa.provider.ldap.ExtendedLdapUserDetails;
import org.cloudfoundry.identity.uaa.user.Mailable;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

import static org.mockito.Mockito.*;

public class UserDetailsBuilder<T extends UserDetails> {
    private T userDetails;

    private UserDetailsBuilder(T mockedUserDetails) {
        userDetails = mockedUserDetails;

        // defaults
        when(userDetails.getUsername()).thenReturn("default_username");
        when(userDetails.getPassword()).thenReturn("default_password");
        when(userDetails.getAuthorities()).thenReturn(null);
        when(userDetails.isAccountNonExpired()).thenReturn(true);
        when(userDetails.isAccountNonLocked()).thenReturn(true);
        when(userDetails.isCredentialsNonExpired()).thenReturn(true);
        when(userDetails.isEnabled()).thenReturn(true);
    }

    public static UserDetailsBuilder<UserDetails> aUserDetails() {
        return new UserDetailsBuilder<>(
                mock(UserDetails.class)
        );
    }

    public static UserDetailsBuilder<UserDetails> aMailableUserDetails() {
        return new UserDetailsBuilder<>(
                mock(UserDetails.class, withSettings().extraInterfaces(Mailable.class))
        );
    }

    public static UserDetailsBuilder<LdapUserDetails> anLdapUserDetails() {
        return new UserDetailsBuilder<>(
                mock(LdapUserDetails.class)
        );
    }

    public static UserDetailsBuilder<ExtendedLdapUserDetails> aMailableExtendedLdapUserDetails() {
        return new UserDetailsBuilder<>(
                mock(ExtendedLdapUserDetails.class, withSettings().extraInterfaces(Mailable.class))
        );
    }

    public T build() {
        return userDetails;
    }

    public UserDetailsBuilder<T> withUsername(String username) {
        when(userDetails.getUsername()).thenReturn(username);
        return this;
    }

    public UserDetailsBuilder<T> withPassword(String password) {
        when(userDetails.getPassword()).thenReturn(password);
        return this;
    }

    public UserDetailsBuilder<T> withEmailAddress(String email) {
        when(((Mailable) userDetails).getEmailAddress()).thenReturn(email);
        return this;
    }
    public UserDetailsBuilder<T> withDn(String dn) {
        when(((LdapUserDetails)userDetails).getDn()).thenReturn(dn);
        return this;
    }

}
