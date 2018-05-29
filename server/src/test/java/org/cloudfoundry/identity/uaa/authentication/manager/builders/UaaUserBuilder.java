package org.cloudfoundry.identity.uaa.authentication.manager.builders;

import org.cloudfoundry.identity.uaa.user.UaaUser;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class UaaUserBuilder {
    private String username = "default_username";
    private String password = "default_password";
    private String origin = "default_origin";
    private String email = "default@email.com";
    private String userId = "default_userId";

    public static UaaUserBuilder aUaaUser() {
        return new UaaUserBuilder();
    }

    public UaaUserBuilder withUsername(String username) {
        this.username = username;
        return this;
    }

    public UaaUserBuilder withPassword(String password) {
        this.password = password;
        return this;
    }

    public UaaUserBuilder withEmail(String email) {
        this.email = email;
        return this;
    }

    public UaaUserBuilder withOrigin(String origin) {
        this.origin = origin;
        return this;
    }

    public UaaUserBuilder withId(String userId) {
        this.userId = userId;
        return this;
    }

    public UaaUser build() {
        UaaUser user = mock(UaaUser.class);
        when(user.getUsername()).thenReturn(username);
        when(user.getId()).thenReturn(userId);
        when(user.getOrigin()).thenReturn(origin);
        when(user.getEmail()).thenReturn(email);
        when(user.getPassword()).thenReturn(password);

        return user;
    }
}
