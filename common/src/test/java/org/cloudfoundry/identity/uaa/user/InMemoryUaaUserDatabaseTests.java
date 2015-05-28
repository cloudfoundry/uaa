package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertSame;

public class InMemoryUaaUserDatabaseTests {

    UaaUser user = new UaaUser("test-id","username","password","email",UaaAuthority.USER_AUTHORITIES,"givenname","familyname", new Date(), new Date(), Origin.UAA,"externalID", false, IdentityZoneHolder.get().getId(), "test-id");
    InMemoryUaaUserDatabase db;
    @Before
    public void setUp() {
        Map<String, UaaUser> users = new HashMap<>();
        users.put(user.getUsername(), user);
        db = new InMemoryUaaUserDatabase(users);
    }


    @Test
    public void testRetrieveUserByName() throws Exception {
        assertSame(user, db.retrieveUserByName(user.getUsername(), user.getOrigin()));
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testRetrieveUserByNameInvalidOrigin() throws Exception {
        db.retrieveUserByName(user.getUsername(), Origin.LDAP);
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testRetrieveUserByNameInvalidUsername() throws Exception {
        db.retrieveUserByName(user.getUsername() + "1", Origin.UAA);
    }

    @Test
    public void testRetrieveUserById() throws Exception {
        assertSame(user, db.retrieveUserById(user.getId()));
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testRetrieveUserByInvalidId() throws Exception {
        db.retrieveUserById(user.getId() + "1");
    }

    @Test
    public void testUpdateUser() throws Exception {
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
            user.getSalt());
        db.updateUser(user.getId(), newUser);
        assertSame(newUser, db.retrieveUserById(user.getId()));
    }
}