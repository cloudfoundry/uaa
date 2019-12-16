package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collections;
import java.util.Date;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

public class InMemoryUaaUserDatabaseTests {

    UaaUser user = new UaaUser("test-id","username","password","email",UaaAuthority.USER_AUTHORITIES,"givenname","familyname", new Date(), new Date(), OriginKeys.UAA,"externalID", false, IdentityZoneHolder.get().getId(), "test-id", new Date());
    InMemoryUaaUserDatabase db;
    @Before
    public void setUp() {
        db = new InMemoryUaaUserDatabase(Collections.singleton(user));
    }


    @Test
    public void testRetrieveUserByName() {
        assertSame(user, db.retrieveUserByName(user.getUsername(), user.getOrigin()));
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testRetrieveUserByNameInvalidOrigin() {
        db.retrieveUserByName(user.getUsername(), OriginKeys.LDAP);
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testRetrieveUserByNameInvalidUsername() {
        db.retrieveUserByName(user.getUsername() + "1", OriginKeys.UAA);
    }

    @Test
    public void testRetrieveUserById() {
        assertSame(user, db.retrieveUserById(user.getId()));
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testRetrieveUserByInvalidId() {
        db.retrieveUserById(user.getId() + "1");
    }

    @Test
    public void retrieveUserByEmail() {
        assertSame(user, db.retrieveUserByEmail(user.getEmail(), OriginKeys.UAA));
    }

    @Test
    public void retrieveUserByEmail_with_invalidEmail() {
        assertNull(db.retrieveUserByEmail("invalid.email@wrong.no", OriginKeys.UAA));
    }

    @Test
    public void testUpdateUser() {
        assertSame(user, db.retrieveUserById(user.getId()));
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
        assertSame(newUser, db.retrieveUserById(user.getId()));
    }

    @Test
    public void updateLastLogonTime() {
        db.updateLastLogonTime("test-id");
        UaaUser uaaUser = db.retrieveUserById("test-id");
        assertNotNull(uaaUser.getLastLogonTime());
    }
}
