package org.cloudfoundry.identity.uaa.scim.jdbc;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Group;
import org.cloudfoundry.identity.uaa.scim.ScimUser.PhoneNumber;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.*;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class JdbcScimUserProvisioningTests {

    private static final String SQL_INJECTION_FIELDS = "password,version,created,lastModified,username,email,givenName,familyName";
    private static final String OLD_ADD_USER_SQL_FORMAT = "insert into users (id, username, password, email, givenName, familyName, phoneNumber) values ('%s','%s','%s','%s','%s', '%s', '%s')";
    private static final String VERIFY_USER_SQL_FORMAT = "select verified from users where id=?";
    private static final String INSERT_MEMBERSHIP = "insert into group_membership (group_id, member_id, member_type,authorities,added, origin, identity_zone_id) values (?,?,?,?,?,?,?)";

    private JdbcScimUserProvisioning jdbcScimUserProvisioning;
    private RandomValueStringGenerator generator;
    private JdbcPagingListFactory pagingListFactory;
    private String joeId;
    private String currentIdentityZoneId;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbcTemplate;
    private String joeEmail;
    private final String JOE_NAME = "joe";

    @BeforeEach
    void setUp(@Autowired LimitSqlAdapter limitSqlAdapter) {
        generator = new RandomValueStringGenerator();
        joeId = "joeId-" + UUID.randomUUID().toString().substring("joeId-".length());
        joeEmail = "joe@joe.com";
        String mabelId = "mabelId-" + UUID.randomUUID().toString().substring("mabelId-".length());
        pagingListFactory = new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter);

        currentIdentityZoneId = "currentIdentityZoneId-" + generator.generate();

        jdbcScimUserProvisioning = new JdbcScimUserProvisioning(jdbcTemplate, pagingListFactory, passwordEncoder);

        SimpleSearchQueryConverter filterConverter = new SimpleSearchQueryConverter();
        Map<String, String> replaceWith = new HashMap<>();
        replaceWith.put("emails\\.value", "email");
        replaceWith.put("groups\\.display", "authorities");
        replaceWith.put("phoneNumbers\\.value", "phoneNumber");
        filterConverter.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));
        jdbcScimUserProvisioning.setQueryConverter(filterConverter);

        addUser(jdbcTemplate, joeId,
                JOE_NAME, passwordEncoder.encode("joespassword"), joeEmail, "Joe", "User", "+1-222-1234567", currentIdentityZoneId);
        addUser(jdbcTemplate, mabelId, "mabel", passwordEncoder.encode("mabelspassword"), "mabel@mabel.com", "Mabel", "User", "", currentIdentityZoneId);
    }

    @AfterEach
    void tearDown() {
        jdbcTemplate.execute("delete from users");
    }


    @WithDatabaseContext
    @Nested
    class WhenFindingByEmailAndZone {
        @Test
        void canRetrieveExistingUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByEmailAndZone(joeEmail, UAA, currentIdentityZoneId);
            assertEquals(1, found.size());

            ScimUser joe = found.get(0);
            assertNotNull(joe);
            assertEquals(joeId, joe.getId());
            assertEquals("Joe", joe.getGivenName());
            assertEquals("User", joe.getFamilyName());
            assertEquals("joe@joe.com", joe.getPrimaryEmail());
            assertEquals("joe", joe.getUserName());
            assertEquals("+1-222-1234567", joe.getPhoneNumbers().get(0).getValue());
            assertNull(joe.getGroups());
        }

        @Test
        void cannotRetrieveNonexistentUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByEmailAndZone("unknown@example.com", UAA, currentIdentityZoneId);
            assertEquals(0, found.size());
        }
    }

    @WithDatabaseContext
    @Nested
    class WhenFindingByUsernameAndOriginAndZone {
        @Test
        void canRetrieveExistingUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByUsernameAndOriginAndZone(JOE_NAME, UAA, currentIdentityZoneId);
            assertEquals(1, found.size());

            ScimUser joe = found.get(0);
            assertNotNull(joe);
            assertEquals(joeId, joe.getId());
            assertEquals("Joe", joe.getGivenName());
            assertEquals("User", joe.getFamilyName());
            assertEquals("joe@joe.com", joe.getPrimaryEmail());
            assertEquals("joe", joe.getUserName());
            assertEquals("+1-222-1234567", joe.getPhoneNumbers().get(0).getValue());
            assertNull(joe.getGroups());
        }

        @Test
        void cannotRetrieveNonexistentUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByUsernameAndOriginAndZone("not-joe", UAA, currentIdentityZoneId);
            assertEquals(0, found.size());
        }
    }

    @WithDatabaseContext
    @Nested
    class WhenFindingByUsernameAndZone {
        @Test
        void canRetrieveExistingUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByUsernameAndZone(JOE_NAME, currentIdentityZoneId);
            assertEquals(1, found.size());

            ScimUser joe = found.get(0);
            assertNotNull(joe);
            assertEquals(joeId, joe.getId());
            assertEquals("Joe", joe.getGivenName());
            assertEquals("User", joe.getFamilyName());
            assertEquals("joe@joe.com", joe.getPrimaryEmail());
            assertEquals("joe", joe.getUserName());
            assertEquals("+1-222-1234567", joe.getPhoneNumbers().get(0).getValue());
            assertNull(joe.getGroups());
        }

        @Test
        void cannotRetrieveNonexistentUser() {
            List<ScimUser> found = jdbcScimUserProvisioning.retrieveByUsernameAndZone("super-not-joe", currentIdentityZoneId);
            assertEquals(0, found.size());
        }
    }

    @Test
    void canCreateUserWithExclamationMarkInUsername() {
        String userName = "jo!!@foo.com";
        ScimUser user = new ScimUser(null, userName, "Jo", "User");
        user.addEmail("email");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertEquals(userName, created.getUserName());
    }

    @Test
    void canDeleteProviderUsersInDefaultZone() {
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(LOGIN_SERVER);
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", IdentityZone.getUaaZoneId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertEquals(LOGIN_SERVER, created.getOrigin());
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from users where origin=? and identity_zone_id=?",
                new Object[]{LOGIN_SERVER, IdentityZone.getUaaZoneId()},
                Integer.class
                ), is(1)
        );
        addMembership(jdbcTemplate, created.getId(), created.getOrigin(), IdentityZone.getUaaZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[]{created.getId()}, Integer.class), is(1));

        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(LOGIN_SERVER)
                        .setIdentityZoneId(IdentityZone.getUaaZoneId());
        jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, IdentityZone.getUaaZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{LOGIN_SERVER, IdentityZone.getUaaZoneId()}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[]{created.getId()}, Integer.class), is(0));
    }

    @Test
    void canDeleteProviderUsersInOtherZone() {
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(LOGIN_SERVER);
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertEquals(LOGIN_SERVER, created.getOrigin());
        assertEquals(currentIdentityZoneId, created.getZoneId());
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{LOGIN_SERVER, currentIdentityZoneId}, Integer.class), is(1));
        addMembership(jdbcTemplate, created.getId(), created.getOrigin(), currentIdentityZoneId);
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[]{created.getId()}, Integer.class), is(1));

        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(LOGIN_SERVER)
                        .setIdentityZoneId(currentIdentityZoneId);
        jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, currentIdentityZoneId));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{LOGIN_SERVER, currentIdentityZoneId}, Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[]{created.getId()}, Integer.class), is(0));
    }

    @WithDatabaseContext
    @Nested
    class WithOtherZone {

        String currentIdentityZoneId;

        @BeforeEach
        void setUp() {
            currentIdentityZoneId = "currentIdentityZoneId-nested-" + generator.generate();
        }

        @Test
        void canDeleteZoneUsers() {
            ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
            user.addEmail("jo@blah.com");
            user.setOrigin(UAA);
            ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
            assertEquals("jo@foo.com", created.getUserName());
            assertNotNull(created.getId());
            assertEquals(UAA, created.getOrigin());
            assertEquals(currentIdentityZoneId, created.getZoneId());
            assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{UAA, currentIdentityZoneId}, Integer.class), is(1));
            addMembership(jdbcTemplate, created.getId(), created.getOrigin(), currentIdentityZoneId);
            assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[]{created.getId()}, Integer.class), is(1));


            IdentityZone zoneToDelete = new IdentityZone();
            zoneToDelete.setId(currentIdentityZoneId);
            jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(zoneToDelete, null, currentIdentityZoneId));
            assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{UAA, currentIdentityZoneId}, Integer.class), is(0));
            assertThat(jdbcTemplate.queryForObject("select count(*) from group_membership where member_id=?", new Object[]{created.getId()}, Integer.class), is(0));
        }

        @Test
        void cannotDeleteUaaProviderUsersInOtherZone() {
            ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
            user.addEmail("jo@blah.com");
            user.setOrigin(UAA);
            ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
            assertEquals("jo@foo.com", created.getUserName());
            assertNotNull(created.getId());
            assertEquals(UAA, created.getOrigin());
            assertEquals(currentIdentityZoneId, created.getZoneId());
            assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{UAA, currentIdentityZoneId}, Integer.class), is(1));
            IdentityProvider loginServer =
                    new IdentityProvider()
                            .setOriginKey(UAA)
                            .setIdentityZoneId(currentIdentityZoneId);
            jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, currentIdentityZoneId));
            assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{UAA, currentIdentityZoneId}, Integer.class), is(1));
        }

    }

    @Test
    void cannotDeleteUaaZoneUsers() {
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setOrigin(UAA);
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", IdentityZone.getUaaZoneId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertEquals(UAA, created.getOrigin());
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{UAA, IdentityZone.getUaaZoneId()}, Integer.class), is(1));
        IdentityProvider loginServer =
                new IdentityProvider()
                        .setOriginKey(UAA)
                        .setIdentityZoneId(IdentityZone.getUaaZoneId());
        jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<>(loginServer, null, currentIdentityZoneId));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users where origin=? and identity_zone_id=?", new Object[]{UAA, IdentityZone.getUaaZoneId()}, Integer.class), is(1));
    }

    @Test
    void canCreateUserInDefaultIdentityZone() {
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", IdentityZone.getUaaZoneId());
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertNotSame(user.getId(), created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertEquals(user.getUserName(), map.get("userName"));
        assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
        assertNull(created.getGroups());
        assertEquals(IdentityZone.getUaaZoneId(), map.get("identity_zone_id"));
        assertNull(user.getPasswordLastModified());
        assertNotNull(created.getPasswordLastModified());
        assertTrue(Math.abs(created.getMeta().getCreated().getTime() - created.getPasswordLastModified().getTime()) < 1001); //1 second at most given MySQL fractionless timestamp
    }

    @Test
    void canModifyPassword() throws Exception {
        ScimUser user = new ScimUser(null, generator.generate() + "@foo.com", "Jo", "User");
        user.addEmail(user.getUserName());
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertNull(user.getPasswordLastModified());
        assertNotNull(created.getPasswordLastModified());
        assertTrue(Math.abs(created.getMeta().getCreated().getTime() - created.getPasswordLastModified().getTime()) < 1001);
        Thread.sleep(10);
        jdbcScimUserProvisioning.changePassword(created.getId(), "j7hyqpassX", "j7hyqpassXXX", currentIdentityZoneId);

        user = jdbcScimUserProvisioning.retrieve(created.getId(), currentIdentityZoneId);
        assertNotNull(user.getPasswordLastModified());
        assertTrue(Math.abs(user.getMeta().getLastModified().getTime() - user.getPasswordLastModified().getTime()) < 1001);
    }

    @Test
    void setPasswordChangeRequired() {
        ScimUser user = new ScimUser(null, generator.generate() + "@foo.com", "Jo", "User");
        user.addEmail(user.getUserName());
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertFalse(jdbcScimUserProvisioning.checkPasswordChangeIndividuallyRequired(created.getId(), currentIdentityZoneId));
        jdbcScimUserProvisioning.updatePasswordChangeRequired(created.getId(), true, currentIdentityZoneId);
        assertTrue(jdbcScimUserProvisioning.checkPasswordChangeIndividuallyRequired(created.getId(), currentIdentityZoneId));
        jdbcScimUserProvisioning.updatePasswordChangeRequired(created.getId(), false, currentIdentityZoneId);
        assertFalse(jdbcScimUserProvisioning.checkPasswordChangeIndividuallyRequired(created.getId(), currentIdentityZoneId));
    }

    @Test
    void canCreateUserInOtherIdentityZone() {
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.addEmail("jo@blah.com");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertNotSame(user.getId(), created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertEquals(user.getUserName(), map.get("userName"));
        assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
        assertNull(created.getGroups());
        assertEquals(currentIdentityZoneId, map.get("identity_zone_id"));
    }

    @Test
    void countUsersAcrossAllZones() {
        createRandomUserInZone(jdbcTemplate, generator, IdentityZone.getUaaZoneId());
        int beginningCount = jdbcScimUserProvisioning.getTotalCount();
        createRandomUserInZone(jdbcTemplate, generator, "zone1");
        assertEquals(beginningCount + 1, jdbcScimUserProvisioning.getTotalCount());
        createRandomUserInZone(jdbcTemplate, generator, "zone2");
        assertEquals(beginningCount + 2, jdbcScimUserProvisioning.getTotalCount());
    }

    @Test
    void validateOriginAndExternalIDDuringCreateAndUpdate() {
        String origin = "test";
        addIdentityProvider(jdbcTemplate, origin);
        String externalId = "testId";
        ScimUser user = new ScimUser(null, "jo@foo.com", "Jo", "User");
        user.setOrigin(origin);
        user.setExternalId(externalId);
        user.addEmail("jo@blah.com");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertEquals("jo@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertNotSame(user.getId(), created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertEquals(user.getUserName(), map.get("userName"));
        assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
        assertNull(created.getGroups());
        assertEquals(origin, created.getOrigin());
        assertEquals(externalId, created.getExternalId());
        String origin2 = "test2";
        addIdentityProvider(jdbcTemplate, origin2);
        String externalId2 = "testId2";
        created.setOrigin(origin2);
        created.setExternalId(externalId2);
        ScimUser updated = jdbcScimUserProvisioning.update(created.getId(), created, currentIdentityZoneId);
        assertEquals(origin2, updated.getOrigin());
        assertEquals(externalId2, updated.getExternalId());
    }

    @Test
    void canCreateUserWithoutGivenNameAndFamilyName() {
        ScimUser user = new ScimUser(null, "jonah@foo.com", null, null);
        user.addEmail("jo@blah.com");
        ScimUser created = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
        assertEquals("jonah@foo.com", created.getUserName());
        assertNotNull(created.getId());
        assertNotSame(user.getId(), created.getId());
        Map<String, Object> map = jdbcTemplate.queryForMap("select * from users where id=?", created.getId());
        assertEquals(user.getUserName(), map.get("userName"));
        assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
        assertNull(created.getGroups());
    }

    @Test
    void canCreateUserWithSingleQuoteInEmailAndUsername() {
        ScimUser user = new ScimUser(null, "ro'gallagher@example.com", "Rob", "O'Gallagher");
        user.addEmail("ro'gallagher@example.com");
        jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);
    }

    @Test
    void cannotCreateScimUserWithEmptyEmail() {
        ScimUser user = new ScimUser(null, "joeyjoejoe", "joe", "young");
        assertThrows(IllegalArgumentException.class, () -> user.addEmail(""));
    }

    @Test
    void canReadScimUserWithMissingEmail() {
        // Create a user with no email address, reflecting previous behavior

        JdbcScimUserProvisioning noValidateProvisioning = new JdbcScimUserProvisioning(jdbcTemplate, pagingListFactory, passwordEncoder) {
            @Override
            public ScimUser retrieve(String id, String zoneId) {
                ScimUser createdUserId = new ScimUser();
                createdUserId.setId(id);
                return createdUserId;
            }
        };

        ScimUser nohbdy = spy(new ScimUser(null, "nohbdy", "Missing", "Email"));
        ScimUser.Email emptyEmail = new ScimUser.Email();
        emptyEmail.setValue("");
        when(nohbdy.getEmails()).thenReturn(Collections.singletonList(emptyEmail));
        when(nohbdy.getPrimaryEmail()).thenReturn("");
        nohbdy.setUserType(UaaAuthority.UAA_ADMIN.getUserType());
        nohbdy.setSalt("salt");
        nohbdy.setPassword(generator.generate());
        nohbdy.setOrigin(OriginKeys.UAA);
        String createdUserId = noValidateProvisioning.create(nohbdy, currentIdentityZoneId).getId();

        jdbcScimUserProvisioning.retrieve(createdUserId, currentIdentityZoneId);
    }

    @Test
    void updateModifiesExpectedData() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        jo.addEmail("jo@blah.com");
        jo.setUserType(UaaAuthority.UAA_ADMIN.getUserType());
        jo.setSalt("salt");

        ScimUser joe = jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId);

        // Can change username
        assertEquals("josephine", joe.getUserName());
        assertEquals("jo@blah.com", joe.getPrimaryEmail());
        assertEquals("Jo", joe.getGivenName());
        assertEquals("NewUser", joe.getFamilyName());
        assertEquals(1, joe.getVersion());
        assertEquals(joeId, joe.getId());
        assertNull(joe.getGroups());
        assertEquals("salt", joe.getSalt());
    }

    @Test
    void updateWithEmptyPhoneListWorks() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        jo.addEmail("jo@blah.com");
        jo.setPhoneNumbers(new ArrayList<>());
        jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId);
    }

    @Test
    void updateWithEmptyPhoneNumberWorks() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        PhoneNumber emptyNumber = new PhoneNumber();
        jo.addEmail("jo@blah.com");
        jo.setPhoneNumbers(Collections.singletonList(emptyNumber));
        jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId);
    }

    @Test
    void updateWithWhiteSpacePhoneNumberWorks() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        PhoneNumber emptyNumber = new PhoneNumber();
        emptyNumber.setValue(" ");
        jo.addEmail("jo@blah.com");
        jo.setPhoneNumbers(Collections.singletonList(emptyNumber));
        jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId);
    }

    @Test
    void updateCannotModifyGroups() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        jo.addEmail("jo@blah.com");
        jo.setGroups(Collections.singleton(new Group(null, "dash/user")));

        ScimUser joe = jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId);

        assertEquals(joeId, joe.getId());
        assertNull(joe.getGroups());
    }

    @Test
    void updateWithWrongVersionIsError() {
        ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
        jo.addEmail("jo@blah.com");
        jo.setVersion(1);
        assertThrows(OptimisticLockingFailureException.class, () -> jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId));
    }

    @Test
    void updateWithBadUsernameIsError() {
        ScimUser jo = jdbcScimUserProvisioning.retrieve(joeId, currentIdentityZoneId);
        jo.setUserName("jo$ephione");
        assertThrows(InvalidScimResourceException.class, () -> jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId));
    }

    @Test
    void updateWithBadUsernameIsOk_For_Non_UAA() {
        ScimUser jo = new ScimUser(null, "jo$ephine", "Jo", "NewUser");
        jo.setOrigin(OriginKeys.LDAP);
        jo.addEmail("jo@blah.com");
        ScimUser joe = jdbcScimUserProvisioning.update(joeId, jo, currentIdentityZoneId);
        assertEquals("jo$ephine", joe.getUserName());
        assertEquals(OriginKeys.LDAP, joe.getOrigin());
    }

    @Test
    void canChangePasswordWithoutOldPassword() {
        jdbcScimUserProvisioning.changePassword(joeId, null, "koala123$marissa", currentIdentityZoneId);
        String storedPassword = jdbcTemplate.queryForObject("SELECT password from users where ID=?", String.class, joeId);
        assertTrue(passwordEncoder.matches("koala123$marissa", storedPassword));
    }

    @Test
    void canChangePasswordWithCorrectOldPassword() {
        jdbcScimUserProvisioning.changePassword(joeId, "joespassword", "koala123$marissa", currentIdentityZoneId);
        String storedPassword = jdbcTemplate.queryForObject("SELECT password from users where ID=?", String.class, joeId);
        assertTrue(passwordEncoder.matches("koala123$marissa", storedPassword));
    }

    @Test
    void cannotChangePasswordNonexistentUser() {
        assertThrows(BadCredentialsException.class,
                () -> jdbcScimUserProvisioning.changePassword(joeId, "notjoespassword", "newpassword", currentIdentityZoneId));
    }

    @Test
    void cannotChangePasswordIfOldPasswordDoesntMatch() {
        assertThrows(ScimResourceNotFoundException.class,
                () -> jdbcScimUserProvisioning.changePassword("9999", null, "newpassword", currentIdentityZoneId));
    }

    @Test
    void canRetrieveExistingUser() {
        ScimUser joe = jdbcScimUserProvisioning.retrieve(joeId, currentIdentityZoneId);
        assertNotNull(joe);
        assertEquals(joeId, joe.getId());
        assertEquals("Joe", joe.getGivenName());
        assertEquals("User", joe.getFamilyName());
        assertEquals("joe@joe.com", joe.getPrimaryEmail());
        assertEquals("joe", joe.getUserName());
        assertEquals("+1-222-1234567", joe.getPhoneNumbers().get(0).getValue());
        assertNull(joe.getGroups());
    }

    @Test
    void cannotRetrieveNonexistentUser() {
        assertThrows(ScimResourceNotFoundException.class,
                () -> jdbcScimUserProvisioning.retrieve("9999", currentIdentityZoneId));
    }

    @Test
    void canDeactivateExistingUser() {
        String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser deletedUser = jdbcScimUserProvisioning.delete(tmpUserId, 0, currentIdentityZoneId);
        assertEquals(1, jdbcTemplate.queryForList("select * from users where id=? and active=?", tmpUserId, false).size());
        assertFalse(deletedUser.isActive());
        assertEquals(1, jdbcScimUserProvisioning.query("username eq \"" + tmpUserId + "\" and active eq false", currentIdentityZoneId).size());
    }

    @Test
    void cannotDeactivateExistingUserAndThenCreateHimAgain() {
        String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser deletedUser = jdbcScimUserProvisioning.delete(tmpUserId, 0, currentIdentityZoneId);
        deletedUser.setActive(true);
        assertThrows(ScimResourceAlreadyExistsException.class,
                () -> jdbcScimUserProvisioning.createUser(deletedUser, "foobarspam1234", currentIdentityZoneId));
    }

    @Test
    void cannotDeactivateNonexistentUser() {
        assertThrows(ScimResourceNotFoundException.class,
                () -> jdbcScimUserProvisioning.delete("9999", 0, currentIdentityZoneId));
    }

    @Test
    void deactivateWithWrongVersionIsError() {
        assertThrows(OptimisticLockingFailureException.class,
                () -> jdbcScimUserProvisioning.delete(joeId, 1, currentIdentityZoneId));
    }

    @Test
    void canDeleteExistingUserThroughEvent() {
        String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserId, currentIdentityZoneId);
        jdbcScimUserProvisioning.setDeactivateOnDelete(false);
        jdbcScimUserProvisioning.onApplicationEvent(new EntityDeletedEvent<Object>(user, mock(Authentication.class), currentIdentityZoneId));
        assertEquals(0, jdbcTemplate.queryForList("select * from users where id=?", tmpUserId).size());
        assertEquals(0, jdbcScimUserProvisioning.query("username eq \"" + tmpUserId + "\"", currentIdentityZoneId).size());
    }

    @Test
    void canDeleteExistingUser() {
        String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        jdbcScimUserProvisioning.setDeactivateOnDelete(false);
        jdbcScimUserProvisioning.delete(tmpUserId, 0, currentIdentityZoneId);
        assertEquals(0, jdbcTemplate.queryForList("select * from users where id=?", tmpUserId).size());
        assertEquals(0, jdbcScimUserProvisioning.query("username eq \"" + tmpUserId + "\"", currentIdentityZoneId).size());
    }

    @Test
    void canDeleteExistingUserAndThenCreateHimAgain() {
        String tmpUserId = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        jdbcScimUserProvisioning.setDeactivateOnDelete(false);
        ScimUser deletedUser = jdbcScimUserProvisioning.delete(tmpUserId, 0, currentIdentityZoneId);
        assertEquals(0, jdbcTemplate.queryForList("select * from users where id=?", tmpUserId).size());

        deletedUser.setActive(true);
        ScimUser user = jdbcScimUserProvisioning.createUser(deletedUser, "foobarspam1234", currentIdentityZoneId);
        assertNotNull(user);
        assertNotNull(user.getId());
        assertNotSame(tmpUserId, user.getId());
        assertEquals(1, jdbcScimUserProvisioning.query("username eq \"" + tmpUserId + "\"", currentIdentityZoneId).size());
    }

    @Test
    void createdUserNotVerified() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        boolean verified = jdbcTemplate.queryForObject(VERIFY_USER_SQL_FORMAT, Boolean.class, tmpUserIdString);
        assertFalse(verified);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertFalse(user.isVerified());
    }

    @Test
    void createUserWithDuplicateUsername() {
        addUser(jdbcTemplate, "cba09242-aa43-4247-9aa0-b5c75c281f94", "user@example.com", "password", "user@example.com", "first", "user", "90438", currentIdentityZoneId);
        ScimUser scimUser = new ScimUser("user-id-2", "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("user@example.com");
        scimUser.setOrigin(OriginKeys.UAA);
        scimUser.setEmails(Collections.singletonList(email));
        scimUser.setPassword("password");

        ScimResourceAlreadyExistsException e = assertThrows(ScimResourceAlreadyExistsException.class,
                () -> jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId));

        Map<String, Object> userDetails = new HashMap<>();
        userDetails.put("active", true);
        userDetails.put("verified", false);
        userDetails.put("user_id", "cba09242-aa43-4247-9aa0-b5c75c281f94");
        assertEquals(HttpStatus.CONFLICT, e.getStatus());
        assertEquals("Username already in use: user@example.com", e.getMessage());
        assertEquals(userDetails, e.getExtraInfo());
    }

    @Test
    void createUserCheckSalt() {
        ScimUser scimUser = new ScimUser("user-id-3", "user3@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("user@example.com");
        scimUser.setEmails(Collections.singletonList(email));
        scimUser.setPassword("password");
        scimUser.setSalt("salt");
        scimUser.setOrigin(OriginKeys.UAA);
        scimUser = jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId);
        assertNotNull(scimUser);
        assertEquals("salt", scimUser.getSalt());
        scimUser.setSalt("newsalt");
        scimUser = jdbcScimUserProvisioning.update(scimUser.getId(), scimUser, currentIdentityZoneId);
        assertNotNull(scimUser);
        assertEquals("newsalt", scimUser.getSalt());
    }

    @Test
    void updateUserPasswordDoesntChange() {
        String username = "user-" + new RandomValueStringGenerator().generate() + "@test.org";
        ScimUser scimUser = new ScimUser(null, username, "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(username);
        scimUser.setEmails(Collections.singletonList(email));
        scimUser.setSalt("salt");
        scimUser = jdbcScimUserProvisioning.createUser(scimUser, "password", currentIdentityZoneId);
        assertNotNull(scimUser);
        assertEquals("salt", scimUser.getSalt());
        scimUser.setSalt("newsalt");

        String passwordHash = jdbcTemplate.queryForObject("select password from users where id=?", new Object[]{scimUser.getId()}, String.class);
        assertNotNull(passwordHash);

        jdbcScimUserProvisioning.changePassword(scimUser.getId(), null, "password", currentIdentityZoneId);
        assertEquals(passwordHash, jdbcTemplate.queryForObject("select password from users where id=?", new Object[]{scimUser.getId()}, String.class));

        jdbcScimUserProvisioning.changePassword(scimUser.getId(), "password", "password", currentIdentityZoneId);
        assertEquals(passwordHash, jdbcTemplate.queryForObject("select password from users where id=?", new Object[]{scimUser.getId()}, String.class));

    }

    @Test
    void createUserWithDuplicateUsernameInOtherIdp() {
        addUser(jdbcTemplate, "cba09242-aa43-4247-9aa0-b5c75c281f94", "user@example.com", "password", "user@example.com", "first", "user", "90438", IdentityZone.getUaaZoneId());

        ScimUser scimUser = new ScimUser(null, "user@example.com", "User", "Example");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("user@example.com");
        scimUser.setEmails(Collections.singletonList(email));
        scimUser.setPassword("password");
        scimUser.setOrigin("test-origin");
        String userId2 = jdbcScimUserProvisioning.create(scimUser, currentIdentityZoneId).getId();
        assertNotNull(userId2);
        assertNotEquals("cba09242-aa43-4247-9aa0-b5c75c281f94", userId2);
    }

    @Test
    void updatedUserVerified() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        boolean verified = jdbcTemplate.queryForObject(VERIFY_USER_SQL_FORMAT, Boolean.class, tmpUserIdString);
        assertFalse(verified);
        jdbcScimUserProvisioning.verifyUser(tmpUserIdString, -1, currentIdentityZoneId);
        verified = jdbcTemplate.queryForObject(VERIFY_USER_SQL_FORMAT, Boolean.class, tmpUserIdString);
        assertTrue(verified);
    }

    @Test
    void createUserWithNoZoneDefaultsToUAAZone() {
        String id = UUID.randomUUID().toString();
        jdbcTemplate.execute(String.format(OLD_ADD_USER_SQL_FORMAT, id, "test-username", "password", "test@email.com", "givenName", "familyName", "1234567890"));
        ScimUser user = jdbcScimUserProvisioning.retrieve(id, IdentityZone.getUaaZoneId());
        assertEquals(IdentityZone.getUaaZoneId(), user.getZoneId());
        assertNull(user.getSalt());
    }

    @Test
    void createUserWithNoZoneFailsIfUserAlreadyExistsInUaaZone() {
        addUser(jdbcTemplate, UUID.randomUUID().toString(), "test-username", "password", "test@email.com", "givenName", "familyName", "1234567890", IdentityZone.getUaaZoneId());
        assertThrows(DuplicateKeyException.class,
                () -> jdbcTemplate.execute(String.format(OLD_ADD_USER_SQL_FORMAT, UUID.randomUUID().toString(), "test-username", "password", "test@email.com", "givenName", "familyName", "1234567890")));
    }

    @Test
    void updatedVersionedUserVerified() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertFalse(user.isVerified());
        user = jdbcScimUserProvisioning.verifyUser(tmpUserIdString, user.getVersion(), currentIdentityZoneId);
        assertTrue(user.isVerified());
    }

    @Test
    void userVerifiedThroughUpdate() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertFalse(user.isVerified());
        user.setVerified(true);
        user = jdbcScimUserProvisioning.update(tmpUserIdString, user, currentIdentityZoneId);
        assertTrue(user.isVerified());
    }

    @Test
    void userVerifiedInvalidUserId() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertFalse(user.isVerified());
        assertThrows(ScimResourceNotFoundException.class, () -> jdbcScimUserProvisioning.verifyUser("-1-1-1", -1, currentIdentityZoneId));
    }

    @Test
    void userUpdateInvalidUserId() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertFalse(user.isVerified());
        user.setVerified(true);
        assertThrows(ScimResourceNotFoundException.class, () -> jdbcScimUserProvisioning.update("-1-1-1", user, currentIdentityZoneId));
    }

    @Test
    void updatedIncorrectVersionUserVerified() {
        String tmpUserIdString = createUserForDelete(jdbcTemplate, currentIdentityZoneId);
        ScimUser user = jdbcScimUserProvisioning.retrieve(tmpUserIdString, currentIdentityZoneId);
        assertFalse(user.isVerified());
        assertThrows(OptimisticLockingFailureException.class, () -> jdbcScimUserProvisioning.verifyUser(tmpUserIdString, user.getVersion() + 50, currentIdentityZoneId));
    }

    @Test
    void cannotDeleteNonexistentUser() {
        jdbcScimUserProvisioning.setDeactivateOnDelete(false);
        assertThrows(ScimResourceNotFoundException.class,
                () -> jdbcScimUserProvisioning.delete("9999", 0, currentIdentityZoneId));
    }

    @Test
    void deleteWithWrongVersionIsError() {
        jdbcScimUserProvisioning.setDeactivateOnDelete(false);
        assertThrows(OptimisticLockingFailureException.class, () -> jdbcScimUserProvisioning.delete(joeId, 1, currentIdentityZoneId));
    }

    @Test
    void canRetrieveUsers() {
        assertTrue(2 <= jdbcScimUserProvisioning.retrieveAll(currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterExists() {
        assertTrue(2 <= jdbcScimUserProvisioning.query("username pr", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterEquals() {
        assertEquals(1, jdbcScimUserProvisioning.query("username eq \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterEqualsDoubleQuote() {
        assertEquals(1, jdbcScimUserProvisioning.query("username eq \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterKeyCaseSensitivity() {
        // This actually depends on the RDBMS.
        assertEquals(1, jdbcScimUserProvisioning.query("USERNAME eq \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterOperatorCaseSensitivity() {
        // This actually depends on the RDBMS.
        assertEquals(1, jdbcScimUserProvisioning.query("username EQ \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterValueCaseSensitivity() {
        // This actually depends on the RDBMS.
        assertEquals(1, jdbcScimUserProvisioning.query("username eq \"Joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterContains() {
        assertEquals(2, jdbcScimUserProvisioning.query("username co \"e\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterStartsWith() {
        assertEquals(1, jdbcScimUserProvisioning.query("username sw \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterGreater() {
        assertEquals(1, jdbcScimUserProvisioning.query("username gt \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithEmailFilter() {
        assertEquals(1, jdbcScimUserProvisioning.query("emails.value sw \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithGroupsFilter() {
        List<ScimUser> users = jdbcScimUserProvisioning.query("groups.display co \"uaa.user\"", currentIdentityZoneId);
        assertEquals(2, users.size());
        for (ScimUser user : users) {
            assertNotNull(user);
        }
    }

    @Test
    void canRetrieveUsersWithPhoneNumberFilter() {
        assertEquals(1, jdbcScimUserProvisioning.query("phoneNumbers.value sw \"+1-222\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithMetaVersionFilter() {
        assertEquals(1, jdbcScimUserProvisioning.query("userName eq \"joe\" and meta.version eq 0", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithMetaDateFilter() {
        assertEquals(2, jdbcScimUserProvisioning.query("meta.created gt \"1970-01-01T00:00:00.000Z\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithBooleanFilter() {
        assertEquals(2, jdbcScimUserProvisioning.query("username pr and active eq true", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithSortBy() {
        assertEquals(2, jdbcScimUserProvisioning.query("username pr", "username", true, currentIdentityZoneId).size());
    }

    @Test
    void throwsExceptionWhenSortByIncludesThePrivateFieldSalt() {
        assertThrowsWithMessageThat(IllegalArgumentException.class,
                () -> jdbcScimUserProvisioning.query("id pr", "ID,     salt     ", true, currentIdentityZoneId).size(),
                is("Invalid sort field: salt")
        );
    }

    @Test
    void canRetrieveUsersWithSortByEmail() {
        assertEquals(2, jdbcScimUserProvisioning.query("username pr", "emails.value", true, currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterBooleanAnd() {
        assertEquals(2, jdbcScimUserProvisioning.query("username pr and emails.value co \".com\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterBooleanOr() {
        assertEquals(2, jdbcScimUserProvisioning.query("username eq \"joe\" or emails.value co \".com\"", currentIdentityZoneId).size());
    }

    @Test
    void canRetrieveUsersWithFilterBooleanOrMatchesSecond() {
        assertEquals(1, jdbcScimUserProvisioning.query("username eq \"foo\" or username eq \"joe\"", currentIdentityZoneId).size());
    }

    @Test
    void cannotRetrieveUsersWithIllegalFilterField() {
        assertThrows(IllegalArgumentException.class,
                () -> assertEquals(2, jdbcScimUserProvisioning.query("emails.type eq \"bar\"", currentIdentityZoneId).size()));
    }

    @Test
    void cannotRetrieveUsersWithIllegalPhoneNumberFilterField() {
        assertThrows(IllegalArgumentException.class,
                () -> assertEquals(2, jdbcScimUserProvisioning.query("phoneNumbers.type eq \"bar\"", currentIdentityZoneId).size()));
    }

    @Test
    void cannotRetrieveUsersWithIllegalFilterQuotes() {
        assertThrows(IllegalArgumentException.class,
                () -> assertEquals(2, jdbcScimUserProvisioning.query("username eq \"bar", currentIdentityZoneId).size()));
    }

    @Test
    void cannotRetrieveUsersWithNativeSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        assertThrows(IllegalArgumentException.class,
                () -> jdbcScimUserProvisioning.query("username=\"joe\"; select " + SQL_INJECTION_FIELDS
                        + " from users where username='joe'", currentIdentityZoneId));
    }

    @Test
    void cannotRetrieveUsersWithSqlInjectionAttackOnGt() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        assertThrows(IllegalArgumentException.class,
                () -> jdbcScimUserProvisioning.query("username gt \"h\"; select " + SQL_INJECTION_FIELDS
                        + " from users where username='joe'", currentIdentityZoneId));
    }

    @Test
    void cannotRetrieveUsersWithSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        assertThrows(IllegalArgumentException.class, () -> jdbcScimUserProvisioning.query("username eq \"joe\"; select " + SQL_INJECTION_FIELDS
                + " from users where username='joe'", currentIdentityZoneId));
    }

    @Test
    void cannotRetrieveUsersWithAnotherSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        assertThrows(IllegalArgumentException.class, () -> jdbcScimUserProvisioning.query("username eq \"joe\"\"; select id from users where id='''; select "
                + SQL_INJECTION_FIELDS + " from users where username='joe'", currentIdentityZoneId));
    }

    @Test
    void cannotRetrieveUsersWithYetAnotherSqlInjectionAttack() {
        String password = jdbcTemplate.queryForObject("select password from users where username='joe'", String.class);
        assertNotNull(password);
        assertThrows(IllegalArgumentException.class,
                () -> jdbcScimUserProvisioning.query("username eq \"joe\"'; select " + SQL_INJECTION_FIELDS
                        + " from users where username='joe''", currentIdentityZoneId));
    }

    @Test
    void filterEqWithoutQuotesIsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> jdbcScimUserProvisioning.query("username eq joe", currentIdentityZoneId));
    }

    @Test
    void checkPasswordMatches_returnsTrue_PasswordMatches() {
        assertTrue(jdbcScimUserProvisioning.checkPasswordMatches(joeId, "joespassword", currentIdentityZoneId));
    }

    @Test
    void checkPasswordMatches_ReturnsFalse_newPasswordSameAsOld() {
        assertFalse(jdbcScimUserProvisioning.checkPasswordMatches(joeId, "notjoepassword", currentIdentityZoneId));
    }

    @Test
    void updateLastLogonTime() {
        ScimUser user = jdbcScimUserProvisioning.retrieve(joeId, currentIdentityZoneId);
        Long timeStampBeforeUpdate = user.getLastLogonTime();
        assertNull(timeStampBeforeUpdate);
        jdbcScimUserProvisioning.updateLastLogonTime(joeId, currentIdentityZoneId);
        user = jdbcScimUserProvisioning.retrieve(joeId, currentIdentityZoneId);
        assertNotNull(user.getLastLogonTime());
    }

    @Test
    void createCustomAttribute() {
        String userName = "jo!!@foo.com";
        ScimUser user = new ScimUser(null, userName, "Jo", "User");
        user.addEmail("email");
        LinkedHashMap<String, String> map = new LinkedHashMap<>();
        map.put("accountNumber", "12345");
        user.setCustomAttributes(map);

        ScimUser createdUser = jdbcScimUserProvisioning.createUser(user, "j7hyqpassX", currentIdentityZoneId);

        assertNotNull(createdUser.getCustomAttributes());
    }

    private static String createUserForDelete(final JdbcTemplate jdbcTemplate, String zoneId) {
        String randomUserId = UUID.randomUUID().toString();
        addUser(jdbcTemplate, randomUserId, randomUserId, "password", randomUserId + "@delete.com", "ToDelete", "User", "+1-234-5678910", zoneId);
        return randomUserId;
    }

    private static void addUser(final JdbcTemplate jdbcTemplate,
                                final String id,
                                final String username,
                                final String password,
                                final String email,
                                final String givenName,
                                final String familyName,
                                final String phoneNumber,
                                final String identityZoneId) {
        String addUserSql = String.format(
                "insert into users (id, username, password, email, givenName, familyName, phoneNumber, identity_zone_id) values ('%s','%s','%s','%s','%s','%s','%s','%s')",
                id,
                username,
                password,
                email,
                givenName,
                familyName,
                phoneNumber,
                identityZoneId);
        jdbcTemplate.execute(addUserSql);
    }

    private static void createRandomUserInZone(
            final JdbcTemplate jdbcTemplate,
            final RandomValueStringGenerator generator,
            final String zoneId) {
        final String id = "scimUserId-" + UUID.randomUUID().toString().substring("scimUserId-".length());
        final String username = "username-" + generator.generate();
        final String password = "password-" + generator.generate();
        final String email = "email-" + generator.generate();
        final String givenName = "givenName-" + generator.generate();
        final String familyName = "familyName-" + generator.generate();
        final String phoneNumber = "phoneNumber-" + generator.generate();

        addUser(jdbcTemplate, id, username, password, email, givenName, familyName, phoneNumber, zoneId);
    }

    private static void addMembership(final JdbcTemplate jdbcTemplate,
                                      final String userId,
                                      final String origin,
                                      final String zoneId) {
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        jdbcTemplate.update(INSERT_MEMBERSHIP, userId, userId, "USER", "authorities", timestamp, origin, zoneId);
    }

    private static void addIdentityProvider(JdbcTemplate jdbcTemplate, String originKey) {
        jdbcTemplate.update("insert into identity_provider (id,identity_zone_id,name,origin_key,type) values (?,'uaa',?,?,'UNKNOWN')", UUID.randomUUID().toString(), originKey, originKey);
    }

}
