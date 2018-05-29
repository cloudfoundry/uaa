package org.cloudfoundry.identity.uaa.authentication.manager.builders;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.springframework.security.core.Authentication;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.authentication.manager.builders.UserDetailsBuilder.aUserDetails;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthenticationBuilder<T extends Authentication> {
    private T authentication;

    private AuthenticationBuilder(T authenticationMock) {
        authentication = authenticationMock;
    }

    public static AuthenticationBuilder<Authentication> anAuthentication() {
        return new AuthenticationBuilder(mock(Authentication.class)).withPrincipal(aUserDetails());
    }

    public static AuthenticationBuilder<UaaAuthentication> aUaaAuthentication() {
        // defaults
        MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
        userAttributes.put("1", Arrays.asList("1"));
        userAttributes.put("2", Arrays.asList("2", "3"));

        Set<String> groups = new HashSet<>(Arrays.asList("role1", "role2", "role3"));

        return new AuthenticationBuilder(mock(UaaAuthentication.class))
                .withUserAttributes(userAttributes)
                .withExternalGroups(groups);
    }

    public T build() {
        return authentication;
    }

    public AuthenticationBuilder<T> withPrincipal(UserDetailsBuilder userDetailsBuilder) {
        when(authentication.getPrincipal()).thenReturn(userDetailsBuilder.build());
        return this;
    }

    public AuthenticationBuilder<T> withPrincipal(Object principal) {
        when(authentication.getPrincipal()).thenReturn(principal);
        return this;
    }

    public AuthenticationBuilder<T> withPrincipal(UaaPrincipalBuilder builder) {
        when(authentication.getPrincipal()).thenReturn(builder.build());
        return this;
    }

    public AuthenticationBuilder<T> withDetails(UaaAuthenticationDetails uaaAuthenticationDetails) {
        when(authentication.getDetails()).thenReturn(uaaAuthenticationDetails);
        return this;
    }

    public AuthenticationBuilder<T> withDetails(UaaAuthenticationDetailsBuilder uaaAuthenticationDetailsBuilder) {
        when(authentication.getDetails()).thenReturn(uaaAuthenticationDetailsBuilder.build());
        return this;
    }

    public AuthenticationBuilder<T> withUserAttributes(MultiValueMap<String, String> userAttributes) {
        when(((UaaAuthentication) authentication).getUserAttributes()).thenReturn(userAttributes);
        return this;
    }

    public AuthenticationBuilder<T> withExternalGroups(Set<String> groups) {
        when(((UaaAuthentication) authentication).getExternalGroups()).thenReturn(groups);
        return this;
    }
}
