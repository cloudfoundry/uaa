package org.cloudfoundry.identity.uaa.user;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InMemoryUaaUserDatabaseTests {

    UaaUser user = new UaaUser("test-id", "username", "password", "email", UaaAuthority.USER_AUTHORITIES, "givenname", "familyname", new Date(), new Date(), OriginKeys.UAA, "externalID", false, IdentityZoneHolder.get().getId(), "test-id", new Date());
    InMemoryUaaUserDatabase db;

    @BeforeEach
    void setUp() {
        db = new InMemoryUaaUserDatabase(Collections.singleton(user));
    }

    @Test
    void retrieveUserByName() {
        assertThat(db.retrieveUserByName(user.getUsername(), user.getOrigin())).isSameAs(user);
    }

    @Test
    void retrieveUserPrototypeByName() {
        assertThat(db.retrieveUserPrototypeByName(user.getUsername(), user.getOrigin()).getUsername()).isSameAs(user.getUsername());
    }

    @Test
    void retrieveUserByNameInvalidOrigin() {
        assertThatThrownBy(() ->
                db.retrieveUserByName(user.getUsername(), OriginKeys.LDAP)).asInstanceOf(InstanceOfAssertFactories.throwable(UsernameNotFoundException.class));
    }

    @Test
    void retrieveUserByNameInvalidUsername() {
        assertThatThrownBy(() ->
                db.retrieveUserByName(user.getUsername() + "1", OriginKeys.UAA)).asInstanceOf(InstanceOfAssertFactories.throwable(UsernameNotFoundException.class));
    }

    @Test
    void retrieveUserById() {
        assertThat(db.retrieveUserById(user.getId())).isSameAs(user);
    }

    @Test
    void retrieveUserPrototypeById() {
        assertThat(db.retrieveUserById(user.getId()).getId()).isSameAs(user.getId());
    }

    @Test
    void retrieveUserByInvalidId() {
        assertThatThrownBy(() ->
                db.retrieveUserById(user.getId() + "1")).asInstanceOf(InstanceOfAssertFactories.throwable(UsernameNotFoundException.class));
    }

    @Test
    void retrieveUserByEmail() {
        assertThat(db.retrieveUserByEmail(user.getEmail(), OriginKeys.UAA)).isSameAs(user);
    }

    @Test
    void retrieveUserPrototypeByEmail() {
        assertThat(db.retrieveUserPrototypeByEmail(user.getEmail(), OriginKeys.UAA).getEmail()).isSameAs(user.getEmail());
    }

    @Test
    void retrieveUserByEmail_with_invalidEmail() {
        assertThat(db.retrieveUserByEmail("invalid.email@wrong.no", OriginKeys.UAA)).isNull();
    }

    @Test
    void updateUser() {
        assertThat(db.retrieveUserById(user.getId())).isSameAs(user);
        UaaUser newUser = new UaaUser(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getEmail(),
                user.getAuthorities(),
                user.getGivenName(),
                user.getFamilyName(),
                user.getCreated(),
                user.getModified(),
                user.getOrigin(),
                user.getExternalId(),
                false,
                user.getZoneId(),
                user.getSalt(),
                user.getPasswordLastModified());
        db.updateUser(user.getId(), newUser);
        assertThat(db.retrieveUserById(user.getId())).isSameAs(newUser);
    }

    @Test
    void updateLastLogonTime() {
        db.updateLastLogonTime("test-id");
        UaaUser uaaUser = db.retrieveUserById("test-id");
        assertThat(uaaUser.getLastLogonTime()).isNotNull();
    }
}
