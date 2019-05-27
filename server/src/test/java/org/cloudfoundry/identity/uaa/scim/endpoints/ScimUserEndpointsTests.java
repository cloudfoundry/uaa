package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.account.UserAccountStatus;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mfa.JdbcUserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.provider.*;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapterFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.*;
import org.cloudfoundry.identity.uaa.scim.exception.*;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.security.IsSelfCheck;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.util.FakePasswordEncoder;
import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MfaConfig;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.verification.VerificationMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConversionException;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.HttpMediaTypeException;
import org.springframework.web.servlet.View;

import java.util.*;

import static java.util.Arrays.asList;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(PollutionPreventionExtension.class)
class ScimUserEndpointsTests {

    private static final String JDSA_VMWARE_COM = "jd'sa@vmware.com";

    private ScimUser joel;

    private ScimUser dale;

    private ScimUserEndpoints scimUserEndpoints;

    private ScimGroupEndpoints scimGroupEndpoints;

    private JdbcScimUserProvisioning jdbcScimUserProvisioning;

    private JdbcUserGoogleMfaCredentialsProvisioning mockJdbcUserGoogleMfaCredentialsProvisioning;

    private JdbcIdentityProviderProvisioning mockJdbcIdentityProviderProvisioning;

    private JdbcScimGroupMembershipManager jdbcScimGroupMembershipManager;

    private JdbcApprovalStore jdbcApprovalStore;

    private static EmbeddedDatabase embeddedDatabase;
    private PasswordValidator mockPasswordValidator;

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private JdbcTemplate jdbcTemplate;
    private FakePasswordEncoder fakePasswordEncoder;

    @BeforeAll
    static void setUpDatabase() {
        EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder();
        embeddedDatabase = builder.build();
        Flyway flyway = new Flyway();
        flyway.setBaselineVersion(MigrationVersion.fromVersion("1.5.2"));
        flyway.setLocations("classpath:/org/cloudfoundry/identity/uaa/db/hsqldb/");
        flyway.setDataSource(embeddedDatabase);
        flyway.migrate();
    }

    @BeforeEach
    void setUp() {
        scimUserEndpoints = new ScimUserEndpoints();
        scimUserEndpoints.setUserMaxCount(5);

        IdentityZoneHolder.clear();
        jdbcTemplate = new JdbcTemplate(embeddedDatabase);
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(jdbcTemplate, LimitSqlAdapterFactory.getLimitSqlAdapter());
        fakePasswordEncoder = new FakePasswordEncoder();
        jdbcScimUserProvisioning = new JdbcScimUserProvisioning(jdbcTemplate, pagingListFactory, fakePasswordEncoder);

        SimpleSearchQueryConverter filterConverter = new SimpleSearchQueryConverter();
        Map<String, String> replaceWith = new HashMap<>();
        replaceWith.put("emails\\.value", "email");
        replaceWith.put("groups\\.display", "authorities");
        replaceWith.put("phoneNumbers\\.value", "phoneNumber");
        filterConverter.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));
        jdbcScimUserProvisioning.setQueryConverter(filterConverter);

        mockJdbcIdentityProviderProvisioning = Mockito.mock(JdbcIdentityProviderProvisioning.class);

        mockJdbcUserGoogleMfaCredentialsProvisioning = Mockito.mock(JdbcUserGoogleMfaCredentialsProvisioning.class);
        scimUserEndpoints.setMfaCredentialsProvisioning(mockJdbcUserGoogleMfaCredentialsProvisioning);

        scimUserEndpoints.setScimUserProvisioning(jdbcScimUserProvisioning);
        scimUserEndpoints.setIdentityProviderProvisioning(mockJdbcIdentityProviderProvisioning);

        mockPasswordValidator = mock(PasswordValidator.class);
        doThrow(new InvalidPasswordException("Password must be at least 1 characters in length."))
                .when(mockPasswordValidator).validate(null);
        doThrow(new InvalidPasswordException("Password must be at least 1 characters in length."))
                .when(mockPasswordValidator).validate(eq(""));
        scimUserEndpoints.setPasswordValidator(mockPasswordValidator);

        jdbcScimGroupMembershipManager = new JdbcScimGroupMembershipManager(jdbcTemplate);
        jdbcScimGroupMembershipManager.setScimUserProvisioning(jdbcScimUserProvisioning);
        JdbcScimGroupProvisioning gdao = new JdbcScimGroupProvisioning(jdbcTemplate, pagingListFactory);
        jdbcScimGroupMembershipManager.setScimGroupProvisioning(gdao);
        IdentityZoneHolder.get().getConfig().getUserConfig().setDefaultGroups(Collections.singletonList("uaa.user"));
        gdao.createOrGet(new ScimGroup(null, "uaa.user", IdentityZoneHolder.get().getId()), IdentityZoneHolder.get().getId());
        scimUserEndpoints.setScimGroupMembershipManager(jdbcScimGroupMembershipManager);
        scimGroupEndpoints = new ScimGroupEndpoints(gdao, jdbcScimGroupMembershipManager);
        scimGroupEndpoints.setGroupMaxCount(5);

        joel = new ScimUser(null, "jdsa", "Joel", "D'sa");
        joel.addEmail(JDSA_VMWARE_COM);
        dale = new ScimUser(null, "olds", "Dale", "Olds");
        dale.addEmail("olds@vmware.com");
        joel = jdbcScimUserProvisioning.createUser(joel, "password", IdentityZoneHolder.get().getId());
        dale = jdbcScimUserProvisioning.createUser(dale, "password", IdentityZoneHolder.get().getId());

        Map<Class<? extends Exception>, HttpStatus> map = new HashMap<>();
        map.put(IllegalArgumentException.class, HttpStatus.BAD_REQUEST);
        map.put(UnsupportedOperationException.class, HttpStatus.BAD_REQUEST);
        map.put(BadSqlGrammarException.class, HttpStatus.BAD_REQUEST);
        map.put(DataIntegrityViolationException.class, HttpStatus.BAD_REQUEST);
        map.put(HttpMessageConversionException.class, HttpStatus.BAD_REQUEST);
        map.put(HttpMediaTypeException.class, HttpStatus.BAD_REQUEST);
        scimUserEndpoints.setStatuses(map);

        jdbcApprovalStore = new JdbcApprovalStore(jdbcTemplate);
        scimUserEndpoints.setApprovalStore(jdbcApprovalStore);

        scimUserEndpoints.setIsSelfCheck(new IsSelfCheck(null));
    }

    @AfterAll
    static void tearDown() {
        if (embeddedDatabase != null) {
            embeddedDatabase.shutdown();
        }
    }

    @AfterEach
    void cleanUp() {
        TestUtils.deleteFrom(jdbcTemplate, "group_membership", "users", "groups", "authz_approvals");
        IdentityZoneHolder.clear();
    }

    private void validateUserGroups(ScimUser user, String... gnm) {
        Set<String> expectedAuthorities = new HashSet<>(asList(gnm));
        expectedAuthorities.add("uaa.user");
        assertNotNull(user.getGroups());
        Logger logger = LoggerFactory.getLogger(getClass());
        logger.debug("user's groups: " + user.getGroups() + ", expecting: " + expectedAuthorities);
        assertEquals(expectedAuthorities.size(), user.getGroups().size());
        for (ScimUser.Group g : user.getGroups()) {
            assertTrue(expectedAuthorities.contains(g.getDisplay()));
        }
    }

    @Test
    void validate_password_for_uaa_only() {
        validate_password_for_uaa_origin_only(times(1), OriginKeys.UAA, "password");
    }

    @Test
    void validate_password_not_called_for_non_uaa() {
        validate_password_for_uaa_origin_only(never(), OriginKeys.LOGIN_SERVER, "");
    }

    @Test
    void password_validation_defaults_to_uaa() {
        validate_password_for_uaa_origin_only(times(1), "", "password");
    }

    private void validate_password_for_uaa_origin_only(VerificationMode verificationMode, String origin, String expectedPassword) {
        ScimUser user = new ScimUser(null, generator.generate(), "GivenName", "FamilyName");
        user.setOrigin(origin);
        user.setPassword("password");
        user.setPrimaryEmail(user.getUserName() + "@test.org");
        ScimUser created = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        assertNotNull(created);
        verify(mockPasswordValidator, verificationMode).validate("password");
        checkCreatedPassword(created, expectedPassword);
    }

    private void checkCreatedPassword(ScimUser created, String expectedPassword) {
        jdbcTemplate.query("select password from users where id=?",
                rs -> {
                    assertTrue(fakePasswordEncoder.matches(expectedPassword, rs.getString(1)));
                },
                created.getId());
    }

    @Test
    void groupsIsSyncedCorrectlyOnCreate() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.setPassword("password");
        user.addEmail("dsyer@vmware.com");
        user.setGroups(Collections.singletonList(new ScimUser.Group(null, "test1")));
        ScimUser created = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        validateUserGroups(created, "uaa.user");
    }

    @Test
    void groupsIsSyncedCorrectlyOnUpdate() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail("dsyer@vmware.com");
        user.setPassword("password");
        ScimUser created = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        validateUserGroups(created, "uaa.user");

        created.setGroups(Collections.singletonList(new ScimUser.Group(null, "test1")));
        ScimUser updated = scimUserEndpoints.updateUser(created, created.getId(), "*", new MockHttpServletRequest(), new MockHttpServletResponse(), null);
        validateUserGroups(updated, "uaa.user");
    }

    @Test
    void groupsIsSyncedCorrectlyOnGet() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.setPassword("password");
        user.addEmail("dsyer@vmware.com");
        ScimUser created = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());

        validateUserGroups(created, "uaa.user");

        ScimGroup g = new ScimGroup(null, "test1", IdentityZoneHolder.get().getId());
        g.setMembers(Collections.singletonList(new ScimGroupMember(created.getId())));
        scimGroupEndpoints.createGroup(g, new MockHttpServletResponse());

        validateUserGroups(scimUserEndpoints.getUser(created.getId(), new MockHttpServletResponse()), "test1");
    }

    @Test
    void approvalsIsSyncedCorrectlyOnCreate() {
        ScimUser user = new ScimUser(null, "vidya", "Vidya", "V");
        user.addEmail("vidya@vmware.com");
        user.setPassword("password");
        user.setApprovals(Collections.singleton(new Approval()
                .setUserId("vidya")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(6000))
                .setStatus(Approval.ApprovalStatus.APPROVED)));
        ScimUser created = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());

        assertNotNull(created.getApprovals());
        assertEquals(1, created.getApprovals().size());
    }

    @Test
    void approvalsIsSyncedCorrectlyOnUpdate() {


        ScimUser user = new ScimUser(null, "vidya", "Vidya", "V");
        user.addEmail("vidya@vmware.com");
        user.setPassword("password");
        user.setApprovals(Collections.singleton(new Approval()
                .setUserId("vidya")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(6000))
                .setStatus(Approval.ApprovalStatus.APPROVED)));
        ScimUser created = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        jdbcApprovalStore.addApproval(new Approval()
                .setUserId(created.getId())
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(6000))
                .setStatus(Approval.ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        jdbcApprovalStore.addApproval(new Approval()
                .setUserId(created.getId())
                .setClientId("c1")
                .setScope("s2")
                .setExpiresAt(Approval.timeFromNow(6000))
                .setStatus(Approval.ApprovalStatus.DENIED), IdentityZoneHolder.get().getId());

        created.setApprovals(Collections.singleton(new Approval()
                .setUserId("vidya")
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(6000))
                .setStatus(Approval.ApprovalStatus.APPROVED)));
        ScimUser updated = scimUserEndpoints.updateUser(created, created.getId(), "*", new MockHttpServletRequest(), new MockHttpServletResponse(), null);
        assertEquals(2, updated.getApprovals().size());
    }

    @Test
    void approvalsIsSyncedCorrectlyOnGet() {
        assertEquals(0, scimUserEndpoints.getUser(joel.getId(), new MockHttpServletResponse()).getApprovals().size());

        jdbcApprovalStore.addApproval(new Approval()
                .setUserId(joel.getId())
                .setClientId("c1")
                .setScope("s1")
                .setExpiresAt(Approval.timeFromNow(6000))
                .setStatus(Approval.ApprovalStatus.APPROVED), IdentityZoneHolder.get().getId());
        jdbcApprovalStore.addApproval(new Approval()
                .setUserId(joel.getId())
                .setClientId("c1")
                .setScope("s2")
                .setExpiresAt(Approval.timeFromNow(6000))
                .setStatus(Approval.ApprovalStatus.DENIED), IdentityZoneHolder.get().getId());

        assertEquals(2, scimUserEndpoints.getUser(joel.getId(), new MockHttpServletResponse()).getApprovals().size());
    }

    @Test
    void createUser_whenPasswordIsInvalid_throwsException() {
        doThrow(new InvalidPasswordException("whaddup")).when(mockPasswordValidator).validate(anyString());
        ScimUserProvisioning mockDao = mock(ScimUserProvisioning.class);
        scimUserEndpoints.setScimUserProvisioning(mockDao);
        String zoneId = IdentityZoneHolder.get().getId();
        when(mockDao.createUser(any(ScimUser.class), anyString(), eq(zoneId))).thenReturn(new ScimUser());

        String userName = "user@example.com";
        ScimUser user = new ScimUser("user1", userName, null, null);
        user.addEmail(userName);
        user.setOrigin(OriginKeys.UAA);
        user.setPassword("some bad password");

        try {
            scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        } catch (InvalidPasswordException e) {
            assertEquals(e.getStatus(), HttpStatus.BAD_REQUEST);
            assertEquals(e.getMessage(), "whaddup");
        }

        verify(mockPasswordValidator).validate("some bad password");
    }


    @Test
    void userWithNoEmailNotAllowed() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.setPassword("password");
        try {
            scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
            fail("Expected InvalidScimResourceException");
        } catch (InvalidScimResourceException e) {
            // expected
            String message = e.getMessage();
            assertTrue("Wrong message: " + message, message.contains("email"));
        }
        JdbcTemplate jdbcTemplate = new JdbcTemplate(embeddedDatabase);
        int count = jdbcTemplate.queryForObject("select count(*) from users where userName=?", new Object[]{"dave"}, Integer.class);
        assertEquals(0, count);
    }

    @Test
    void create_uaa_user_when_internal_user_management_is_disabled() {
        assertThrows(InternalUserManagementDisabledException.class,
                () -> create_user_when_internal_user_management_is_disabled(OriginKeys.UAA));
    }

    @Test
    void create_ldap_user_when_internal_user_management_is_disabled() {
        create_user_when_internal_user_management_is_disabled(OriginKeys.LDAP);
    }

    @Test
    void create_with_non_uaa_origin_does_not_validate_password() {
        ScimUser user = spy(new ScimUser(null, "dave", "David", "Syer"));
        user.addEmail(new RandomValueStringGenerator().generate() + "@test.org");
        user.setOrigin("google");
        user.setPassword("bla bla");
        MockHttpServletRequest request = new MockHttpServletRequest();
        scimUserEndpoints.createUser(user, request, new MockHttpServletResponse());
        ArgumentCaptor<String> passwords = ArgumentCaptor.forClass(String.class);
        verify(user, atLeastOnce()).setPassword(passwords.capture());

        //1. this method, 2. user scimUserEndpoints, 3. user provisioning
        assertEquals(3, passwords.getAllValues().size());
        assertEquals("bla bla", passwords.getAllValues().get(0));
        assertEquals("", passwords.getAllValues().get(1));
    }


    private void create_user_when_internal_user_management_is_disabled(String origin) {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail(new RandomValueStringGenerator().generate() + "@test.org");
        user.setOrigin(origin);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(DisableInternalUserManagementFilter.DISABLE_INTERNAL_USER_MANAGEMENT, true);
        scimUserEndpoints.createUser(user, request, new MockHttpServletResponse());
    }

    @Test
    void testHandleExceptionWithConstraintViolation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        scimUserEndpoints.setMessageConverters(new HttpMessageConverter<?>[]{new ExceptionReportHttpMessageConverter()});
        View view = scimUserEndpoints.handleException(new DataIntegrityViolationException("foo"), request);
        ConvertingExceptionView converted = (ConvertingExceptionView) view;
        converted.render(Collections.emptyMap(), request, response);
        String body = response.getContentAsString();
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
        // System.err.println(body);
        assertTrue("Wrong body: " + body, body.contains("message\":\"foo"));
    }

    @Test
    void testHandleExceptionWithBadFieldName() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        scimUserEndpoints.setMessageConverters(new HttpMessageConverter<?>[]{new ExceptionReportHttpMessageConverter()});
        View view = scimUserEndpoints.handleException(new HttpMessageConversionException("foo"), request);
        ConvertingExceptionView converted = (ConvertingExceptionView) view;
        converted.render(Collections.emptyMap(), request, response);
        String body = response.getContentAsString();
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
        // System.err.println(body);
        assertTrue("Wrong body: " + body, body.contains("message\":\"foo"));
    }

    @Test
    void userCanInitializePassword() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail("dsyer@vmware.com");
        ReflectionTestUtils.setField(user, "password", "foo");
        ScimUser created = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        assertNull("A newly created user revealed its password", created.getPassword());
        JdbcTemplate jdbcTemplate = new JdbcTemplate(embeddedDatabase);
        String password = jdbcTemplate.queryForObject("select password from users where id=?", String.class,
                created.getId());
        assertTrue(fakePasswordEncoder.matches("foo", password));
    }

    @Test
    void deleteIsAllowedWithCorrectVersionInEtag() {
        ScimUser exGuy = new ScimUser(null, "deleteme", "Expendable", "Guy");
        exGuy.addEmail("exguy@imonlyheretobedeleted.com");
        exGuy = jdbcScimUserProvisioning.createUser(exGuy, "exguyspassword", IdentityZoneHolder.get().getId());
        scimUserEndpoints.deleteUser(exGuy.getId(), Integer.toString(exGuy.getMeta().getVersion()),
                new MockHttpServletRequest(), new MockHttpServletResponse());
    }

    @Test
    void deleteIsAllowedWithQuotedEtag() {
        ScimUser exGuy = new ScimUser(null, "deleteme", "Expendable", "Guy");
        exGuy.addEmail("exguy@imonlyheretobedeleted.com");
        exGuy = jdbcScimUserProvisioning.createUser(exGuy, "exguyspassword", IdentityZoneHolder.get().getId());
        scimUserEndpoints.deleteUser(exGuy.getId(), "\"*", new MockHttpServletRequest(), new MockHttpServletResponse());
    }

    @Test
    void deleteIs_Not_Allowed_For_UAA_When_InternalUserManagement_Is_Disabled() {
        assertThrows(InternalUserManagementDisabledException.class,
                () -> test_Delete_When_InternalUserManagement_Is_Disabled(OriginKeys.UAA));
    }

    @Test
    void deleteIs_Allowed_For_LDAP_When_InternalUserManagement_Is_Disabled() {
        test_Delete_When_InternalUserManagement_Is_Disabled(OriginKeys.LDAP);
    }

    private void test_Delete_When_InternalUserManagement_Is_Disabled(String origin) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(DisableInternalUserManagementFilter.DISABLE_INTERNAL_USER_MANAGEMENT, true);
        ScimUser exGuy = new ScimUser(null, "deleteme", "Expendable", "Guy");
        exGuy.setOrigin(origin);
        exGuy.addEmail("exguy@imonlyheretobedeleted.com");
        exGuy = jdbcScimUserProvisioning.createUser(exGuy, "exguyspassword", IdentityZoneHolder.get().getId());
        scimUserEndpoints.deleteUser(exGuy.getId(), "\"*", request, new MockHttpServletResponse());
    }


    @Test
    void deleteIsNotAllowedWithWrongVersionInEtag() {
        ScimUser exGuy = new ScimUser(null, "deleteme2", "Expendable", "Guy");
        exGuy.addEmail("exguy2@imonlyheretobedeleted.com");
        exGuy = jdbcScimUserProvisioning.createUser(exGuy, "exguyspassword", IdentityZoneHolder.get().getId());
        final String exGuyId = exGuy.getId();
        final ScimMeta exGuyMeta = exGuy.getMeta();
        assertThrows(OptimisticLockingFailureException.class, () ->
                scimUserEndpoints.deleteUser(
                        exGuyId,
                        Integer.toString(exGuyMeta.getVersion() + 1),
                        new MockHttpServletRequest(),
                        new MockHttpServletResponse()));
    }

    @Test
    void deleteIsAllowedWithNullEtag() {
        ScimUser exGuy = new ScimUser(null, "deleteme3", "Expendable", "Guy");
        exGuy.addEmail("exguy3@imonlyheretobedeleted.com");
        exGuy = jdbcScimUserProvisioning.createUser(exGuy, "exguyspassword", IdentityZoneHolder.get().getId());
        scimUserEndpoints.deleteUser(exGuy.getId(), null, new MockHttpServletRequest(), new MockHttpServletResponse());
    }

    @Test
    void deleteUserUpdatesGroupMembership() {
        ScimUser exGuy = new ScimUser(null, "deleteme3", "Expendable", "Guy");
        exGuy.addEmail("exguy3@imonlyheretobedeleted.com");
        exGuy = jdbcScimUserProvisioning.createUser(exGuy, "exguyspassword", IdentityZoneHolder.get().getId());

        ScimGroup g = new ScimGroup(null, "test1", IdentityZoneHolder.get().getId());
        g.setMembers(Collections.singletonList(new ScimGroupMember(exGuy.getId())));
        g = scimGroupEndpoints.createGroup(g, new MockHttpServletResponse());
        validateGroupMembers(g, exGuy.getId(), true);

        scimUserEndpoints.deleteUser(exGuy.getId(), "*", new MockHttpServletRequest(), new MockHttpServletResponse());
        validateGroupMembers(scimGroupEndpoints.getGroup(g.getId(), new MockHttpServletResponse()), exGuy.getId(), false);
    }


    @Test
    void deleteUserInZoneUpdatesGroupMembership() {
        IdentityZone zone = new IdentityZone();
        zone.setId("not-uaa");
        zone.setSubdomain("not-uaa");
        zone.setName("not-uaa");
        zone.setDescription("not-uaa");
        IdentityZoneHolder.set(zone);

        ScimUser exGuy = new ScimUser(null, "deleteme3", "Expendable", "Guy");
        exGuy.addEmail("exguy3@imonlyheretobedeleted.com");
        exGuy = jdbcScimUserProvisioning.createUser(exGuy, "exguyspassword", IdentityZoneHolder.get().getId());
        assertEquals(IdentityZoneHolder.get().getId(), exGuy.getZoneId());

        ScimGroup g = new ScimGroup(null, "test1", IdentityZoneHolder.get().getId());
        g.setMembers(Collections.singletonList(new ScimGroupMember(exGuy.getId())));
        g = scimGroupEndpoints.createGroup(g, new MockHttpServletResponse());
        validateGroupMembers(g, exGuy.getId(), true);

        scimUserEndpoints.deleteUser(exGuy.getId(), "*", new MockHttpServletRequest(), new MockHttpServletResponse());
        validateGroupMembers(scimGroupEndpoints.getGroup(g.getId(), new MockHttpServletResponse()), exGuy.getId(), false);
    }

    private void validateGroupMembers(ScimGroup g, String mId, boolean expected) {
        boolean isMember = false;
        for (ScimGroupMember m : g.getMembers()) {
            if (mId.equals(m.getMemberId())) {
                isMember = true;
                break;
            }
        }
        assertEquals(expected, isMember);
    }

    @Test
    void testFindAllIds() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "id pr", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
    }

    @Test
    void testFindGroupsAndApprovals() {
        ScimUserEndpoints spy = spy(scimUserEndpoints);
        SearchResults<?> results = spy.findUsers("id,groups,approvals", "id pr", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        verify(spy, times(2)).syncGroups(any(ScimUser.class));
        verify(spy, times(2)).syncApprovals(any(ScimUser.class));
    }

    @Test
    void testFindPageOfIds() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "id pr", null, "ascending", 1, 1);
        assertEquals(2, results.getTotalResults());
        assertEquals(1, results.getResources().size());
    }

    @Test
    void testFindMultiplePagesOfIds() {
        jdbcScimUserProvisioning.setPageSize(1);
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "id pr", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertEquals(2, results.getResources().size());
    }

    @Test
    void testFindWhenStartGreaterThanTotal() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "id pr", null, "ascending", 3, 100);
        assertEquals(2, results.getTotalResults());
        assertEquals(0, results.getResources().size());
    }

    @Test
    void testFindAllNames() {
        SearchResults<?> results = scimUserEndpoints.findUsers("userName", "id pr", null, "ascending", 1, 100);
        Collection<Object> values = getSetFromMaps(results.getResources(), "userName");
        assertTrue(values.contains("olds"));
    }

    @Test
    void testFindAllNamesWithStartIndex() {
        SearchResults<?> results = scimUserEndpoints.findUsers("name", "id pr", null, "ascending", 1, 100);
        assertEquals(2, results.getResources().size());

        results = scimUserEndpoints.findUsers("name", "id pr", null, "ascending", 2, 100);
        assertEquals(1, results.getResources().size());

        results = scimUserEndpoints.findUsers("name", "id pr", null, "ascending", 3, 100);
        assertEquals(0, results.getResources().size());
    }

    @Test
    void testFindAllEmails() {
        SearchResults<?> results = scimUserEndpoints.findUsers("emails.value", "id pr", null, "ascending", 1, 100);
        Collection<Object> values = getSetFromMaps(results.getResources(), "emails.value");
        assertTrue(values.contains(Collections.singletonList("olds@vmware.com")));
    }

    @Test
    void testFindAllAttributes() {
        scimUserEndpoints.findUsers("id", "id pr", null, "ascending", 1, 100);
        SearchResults<Map<String, Object>> familyNames = (SearchResults<Map<String, Object>>) scimUserEndpoints.findUsers("familyName", "id pr", "familyName", "ascending", 1, 100);
        SearchResults<Map<String, Object>> givenNames = (SearchResults<Map<String, Object>>) scimUserEndpoints.findUsers("givenName", "id pr", "givenName", "ascending", 1, 100);
        scimUserEndpoints.findUsers("phoneNumbers", "id pr", null, "ascending", 1, 100);
        scimUserEndpoints.findUsers("externalId", "id pr", null, "ascending", 1, 100);
        scimUserEndpoints.findUsers("meta.version", "id pr", null, "ascending", 1, 100);
        scimUserEndpoints.findUsers("meta.created", "id pr", null, "ascending", 1, 100);
        scimUserEndpoints.findUsers("meta.lastModified", "id pr", null, "ascending", 1, 100);
        scimUserEndpoints.findUsers("zoneId", "id pr", null, "ascending", 1, 100);

        assertThat(familyNames.getResources(), hasSize(2));

        Map<String, Object> dSaMap = familyNames.getResources().get(0);
        assertEquals("D'sa", dSaMap.get("familyName"));

        Map<String, Object> oldsMap = familyNames.getResources().get(1);
        assertEquals("Olds", oldsMap.get("familyName"));

        assertThat(givenNames.getResources(), hasSize(2));

        Map<String, Object> daleMap = givenNames.getResources().get(0);
        assertEquals("Dale", daleMap.get("givenName"));

        Map<String, Object> joelMap = givenNames.getResources().get(1);
        assertEquals("Joel", joelMap.get("givenName"));
    }

    @Test
    void testFindNonExistingAttributes() {
        String nonExistingAttribute = "blabla";
        List<Map<String, Object>> resources = (List<Map<String, Object>>) scimUserEndpoints.findUsers(nonExistingAttribute, "id pr", null, "ascending", 1, 100).getResources();
        for (Map<String, Object> resource : resources) {
            assertNull(resource.get(nonExistingAttribute));
        }
    }

    @Test
    void testFindUsersGroupsSyncedByDefault() {
        ScimGroupMembershipManager mockgroupMembershipManager = mock(ScimGroupMembershipManager.class);
        scimUserEndpoints.setScimGroupMembershipManager(mockgroupMembershipManager);

        scimUserEndpoints.findUsers("", "id pr", null, "ascending", 1, 100);
        verify(mockgroupMembershipManager, atLeastOnce()).getGroupsWithMember(anyString(), anyBoolean(), eq(IdentityZoneHolder.get().getId()));

        scimUserEndpoints.setScimGroupMembershipManager(jdbcScimGroupMembershipManager);
    }

    @Test
    void testFindUsersGroupsSyncedIfIncluded() {
        ScimGroupMembershipManager mockgroupMembershipManager = mock(ScimGroupMembershipManager.class);
        scimUserEndpoints.setScimGroupMembershipManager(mockgroupMembershipManager);

        scimUserEndpoints.findUsers("groups", "id pr", null, "ascending", 1, 100);
        verify(mockgroupMembershipManager, atLeastOnce()).getGroupsWithMember(anyString(), anyBoolean(), eq(IdentityZoneHolder.get().getId()));

        scimUserEndpoints.setScimGroupMembershipManager(jdbcScimGroupMembershipManager);
    }

    @Test
    void testFindUsersGroupsNotSyncedIfNotIncluded() {
        ScimGroupMembershipManager mockgroupMembershipManager = mock(ScimGroupMembershipManager.class);
        scimUserEndpoints.setScimGroupMembershipManager(mockgroupMembershipManager);

        scimUserEndpoints.findUsers("emails.value", "id pr", null, "ascending", 1, 100);
        verifyZeroInteractions(mockgroupMembershipManager);

        scimUserEndpoints.setScimGroupMembershipManager(jdbcScimGroupMembershipManager);
    }

    @Test
    void testFindUsersApprovalsSyncedByDefault() {
        ApprovalStore mockApprovalStore = mock(ApprovalStore.class);
        scimUserEndpoints.setApprovalStore(mockApprovalStore);

        scimUserEndpoints.findUsers("", "id pr", null, "ascending", 1, 100);
        verify(mockApprovalStore, atLeastOnce()).getApprovalsForUser(anyString(), eq(IdentityZoneHolder.get().getId()));

        scimUserEndpoints.setApprovalStore(jdbcApprovalStore);
    }

    @Test
    void testFindUsersApprovalsSyncedIfIncluded() {
        ApprovalStore mockApprovalStore = mock(ApprovalStore.class);
        scimUserEndpoints.setApprovalStore(mockApprovalStore);

        scimUserEndpoints.findUsers("approvals", "id pr", null, "ascending", 1, 100);
        verify(mockApprovalStore, atLeastOnce()).getApprovalsForUser(anyString(), eq(IdentityZoneHolder.get().getId()));

        scimUserEndpoints.setApprovalStore(jdbcApprovalStore);
    }

    @Test
    void testFindUsersApprovalsNotSyncedIfNotIncluded() {
        ApprovalStore mockApprovalStore = mock(ApprovalStore.class);
        scimUserEndpoints.setApprovalStore(mockApprovalStore);

        scimUserEndpoints.findUsers("emails.value", "id pr", null, "ascending", 1, 100);
        verifyZeroInteractions(mockApprovalStore);

        scimUserEndpoints.setApprovalStore(jdbcApprovalStore);
    }

    @Test
    void whenSettingAnInvalidUserMaxCount_ScimUsersEndpointShouldThrowAnException() {
        assertThrowsWithMessageThat(IllegalArgumentException.class, () -> scimUserEndpoints.setUserMaxCount(0), containsString("Invalid \"userMaxCount\" value (got 0). Should be positive number."));
    }

    @Test
    void whenSettingANegativeValueUserMaxCount_ScimUsersEndpointShouldThrowAnException() {
        assertThrowsWithMessageThat(IllegalArgumentException.class, () -> scimUserEndpoints.setUserMaxCount(-1), containsString("Invalid \"userMaxCount\" value (got -1). Should be positive number."));
    }

    @Test
    void testInvalidFilterExpression() {
        assertThrowsWithMessageThat(ScimException.class, () -> scimUserEndpoints.findUsers("id", "userName qq 'd'", null, "ascending", 1, 100), containsString("Invalid filter"));
    }

    @Test
    void testValidFilterExpression() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "userName eq \"d\"", "created", "ascending", 1, 100);
        assertEquals(0, results.getTotalResults());
    }

    @Test
    void testInvalidOrderByExpression() {
        assertThrowsWithMessageThat(
                ScimException.class,
                () -> scimUserEndpoints.findUsers("id", "userName eq \"d\"", "created,unknown", "ascending", 1, 100),
                containsString("Invalid filter"));
    }

    @Test
    void cannotOrderBySalt() {
        assertThrowsWithMessageThat(
                ScimException.class,
                () -> scimUserEndpoints.findUsers("id", "", "salt", "ascending", 1, 100),
                containsString("Invalid filter"));
    }

    @Test
    void testValidOrderByExpression() {
        scimUserEndpoints.findUsers("id", "userName eq \"d\"", "1,created", "ascending", 1, 100);
        scimUserEndpoints.findUsers("id", "userName eq \"d\"", "1,2", "ascending", 1, 100);
        scimUserEndpoints.findUsers("id", "userName eq \"d\"", "username,created", "ascending", 1, 100);
    }

    @SuppressWarnings("unchecked")
    @Test
    void testFindIdsByUserName() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "userName eq \"jdsa\"", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertEquals(1, results.getSchemas().size()); // System.err.println(results.getValues());
        assertEquals(joel.getId(), ((Map<String, Object>) results.getResources().iterator().next()).get("id"));
    }

    @SuppressWarnings("unchecked")
    @Test
    void testFindIdsByEmailApostrophe() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "emails.value eq \"" + JDSA_VMWARE_COM + "\"", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertEquals(1, results.getSchemas().size()); // System.err.println(results.getValues());
        assertEquals(joel.getId(), ((Map<String, Object>) results.getResources().iterator().next()).get("id"));
    }

    @Test
    void testFindIdsByUserNameContains() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "userName co \"d\"", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    void testFindIdsByUserNameStartWith() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "userName sw \"j\"", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    void testFindIdsByEmailContains() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "emails.value sw \"j\"", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    void testFindIdsByEmailContainsWithEmptyResult() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "emails.value sw \"z\"", null, "ascending", 1, 100);
        assertEquals(0, results.getTotalResults());
    }

    @Test
    void testFindIdsWithBooleanExpression() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "userName co \"d\" and id pr", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    void testFindIdsWithBooleanExpressionIvolvingEmails() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id",
                "userName co \"d\" and emails.value co \"vmware\"", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    void testCreateIncludesETagHeader() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.setPassword("password");
        user.addEmail("dave@vmware.com");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        scimUserEndpoints.createUser(user, new MockHttpServletRequest(), httpServletResponse);
        assertEquals("\"0\"", httpServletResponse.getHeader("ETag"));
    }

    @Test
    void testGetIncludesETagHeader() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.setPassword("password");
        user.addEmail("dave@vmware.com");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        scimUserEndpoints.getUser(joel.getId(), httpServletResponse);
        assertEquals("\"0\"", httpServletResponse.getHeader("ETag"));
    }

    @Test
    void testUpdateIncludesETagHeader() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.setPassword("password");
        user.addEmail("dave@vmware.com");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        scimUserEndpoints.updateUser(joel, joel.getId(), "*", new MockHttpServletRequest(), httpServletResponse, null);
        assertEquals("\"1\"", httpServletResponse.getHeader("ETag"));
    }

    @Test
    void test_update_when_internal_user_management_is_disabled_for_uaa() {
        assertThrows(InternalUserManagementDisabledException.class,
                () -> update_when_internal_user_management_is_disabled(OriginKeys.UAA));
    }

    @Test
    void test_update_when_internal_user_management_is_disabled_for_ldap() {
        update_when_internal_user_management_is_disabled(OriginKeys.LDAP);
    }

    private void update_when_internal_user_management_is_disabled(String origin) {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.setPassword("password");
        user.addEmail("dave@vmware.com");
        user.setOrigin(origin);

        user = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());

        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(DisableInternalUserManagementFilter.DISABLE_INTERNAL_USER_MANAGEMENT, true);
        scimUserEndpoints.updateUser(user, user.getId(), "*", request, httpServletResponse, null);
    }

    @Test
    void testVerifyIncludesETagHeader() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.setPassword("password");
        user.addEmail("dave@vmware.com");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        scimUserEndpoints.verifyUser("" + joel.getId(), "*", httpServletResponse);
        assertEquals("\"0\"", httpServletResponse.getHeader("ETag"));
    }

    @SuppressWarnings("unchecked")
    @Test
    void legacyTestFindIdsByUserName() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "userName eq 'jdsa'", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertEquals(1, results.getSchemas().size()); // System.err.println(results.getValues());
        assertEquals(joel.getId(), ((Map<String, Object>) results.getResources().iterator().next()).get("id"));
    }

    @Test
    void legacyTestFindIdsByUserNameContains() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "userName co 'd'", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    void legacyTestFindIdsByUserNameStartWith() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "userName sw 'j'", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    void legacyTestFindIdsByEmailContains() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "emails.value sw 'j'", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    void legacyTestFindIdsByEmailContainsWithEmptyResult() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "emails.value sw 'z'", null, "ascending", 1, 100);
        assertEquals(0, results.getTotalResults());
    }

    @Test
    void legacyTestFindIdsWithBooleanExpression() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id", "userName co 'd' and id pr", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    void legacyTestFindIdsWithBooleanExpressionIvolvingEmails() {
        SearchResults<?> results = scimUserEndpoints.findUsers("id",
                "userName co 'd' and emails.value co 'vmware'", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    void zeroUsersInADifferentIdentityZone() {
        IdentityZone zone = new IdentityZone();
        zone.setId("not-uaa");
        zone.setSubdomain("not-uaa");
        zone.setName("not-uaa");
        zone.setDescription("not-uaa");
        IdentityZoneHolder.set(zone);
        SearchResults<?> results = scimUserEndpoints.findUsers("id",
                "id pr", null, "ascending", 1, 100);
        assertEquals(0, results.getTotalResults());
    }

    @SuppressWarnings("unchecked")
    private Collection<Object> getSetFromMaps(Collection<?> resources, String key) {
        Collection<Object> result = new ArrayList<>();
        for (Object map : resources) {
            result.add(((Map<String, Object>) map).get(key));
        }
        return result;
    }

    @Test
    void testPatchUserNoChange() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        ScimUser createdUser = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        ScimUser patchedUser = scimUserEndpoints.patchUser(createdUser, createdUser.getId(), Integer.toString(user.getVersion()), new MockHttpServletRequest(), new MockHttpServletResponse(), null);
        assertEquals(user.getUserName(), patchedUser.getUserName());
        assertEquals(user.getName().getGivenName(), patchedUser.getName().getGivenName());
        assertEquals(user.getName().getFamilyName(), patchedUser.getName().getFamilyName());
        assertEquals(user.getEmails().size(), patchedUser.getEmails().size());
        assertEquals(user.getPrimaryEmail(), patchedUser.getPrimaryEmail());
        assertEquals(createdUser.getVersion() + 1, patchedUser.getVersion());
    }

    @Test
    void testPatchUser() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        ScimUser createdUser = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        createdUser.setUserName(null);
        createdUser.getMeta().setAttributes(new String[]{"Name"});
        createdUser.setName(null);
        ScimUser.PhoneNumber number = new ScimUser.PhoneNumber("0123456789");
        createdUser.setPhoneNumbers(Collections.singletonList(number));
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("example@example.org");
        email.setPrimary(true);
        createdUser.setEmails(Collections.singletonList(email));
        ScimUser patchedUser = scimUserEndpoints.patchUser(createdUser, createdUser.getId(), Integer.toString(createdUser.getVersion()), new MockHttpServletRequest(), new MockHttpServletResponse(), null);
        assertEquals(createdUser.getId(), patchedUser.getId());
        assertEquals(user.getUserName(), patchedUser.getUserName());
        assertNull(patchedUser.getName().getFamilyName());
        assertNull(patchedUser.getName().getGivenName());
        assertEquals(1, patchedUser.getPhoneNumbers().size());
        assertEquals("0123456789", patchedUser.getPhoneNumbers().get(0).getValue());
        assertEquals("example@example.org", patchedUser.getPrimaryEmail());
        assertEquals(createdUser.getVersion() + 1, patchedUser.getVersion());
    }

    @Test
    void testPatchUnknownUserFails() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.addEmail("test@example.org");
        assertThrows(ScimResourceNotFoundException.class,
                () -> scimUserEndpoints.patchUser(
                        user,
                        UUID.randomUUID().toString(),
                        "0",
                        new MockHttpServletRequest(),
                        new MockHttpServletResponse(),
                        null));
    }

    @Test
    void testPatchEmpty() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        ScimUser createdUser = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        user = new ScimUser();
        ScimUser patchedUser = scimUserEndpoints.patchUser(user, createdUser.getId(), Integer.toString(createdUser.getVersion()), new MockHttpServletRequest(), new MockHttpServletResponse(), null);
        assertEquals(createdUser.getUserName(), patchedUser.getUserName());
        assertEquals(createdUser.getName().getGivenName(), patchedUser.getName().getGivenName());
        assertEquals(createdUser.getName().getFamilyName(), patchedUser.getName().getFamilyName());
        assertEquals(createdUser.getEmails().size(), patchedUser.getEmails().size());
        assertEquals(createdUser.getPrimaryEmail(), patchedUser.getPrimaryEmail());
        assertEquals(createdUser.getVersion() + 1, patchedUser.getVersion());
    }

    @Test
    void testPatchDropUnknownAttributeFails() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        ScimUser createdUser = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        createdUser.getMeta().setAttributes(new String[]{"attributeName"});
        assertThrows(InvalidScimResourceException.class, () -> scimUserEndpoints.patchUser(createdUser, createdUser.getId(), Integer.toString(createdUser.getVersion()), new MockHttpServletRequest(), new MockHttpServletResponse(), null));
    }

    @Test
    void testPatchIncorrectVersionFails() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        ScimUser createdUser = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        assertThrows(ScimResourceConflictException.class, () -> scimUserEndpoints.patchUser(createdUser, createdUser.getId(), Integer.toString(createdUser.getVersion() + 1), new MockHttpServletRequest(), new MockHttpServletResponse(), null));
    }

    @Test
    void testPatchUserStatus() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        ScimUser createdUser = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        UserAccountStatus userAccountStatus = new UserAccountStatus();
        userAccountStatus.setLocked(false);
        UserAccountStatus updatedStatus = scimUserEndpoints.updateAccountStatus(userAccountStatus, createdUser.getId());
        assertEquals(false, updatedStatus.getLocked());
    }

    @Test
    void testPatchUserInvalidStatus() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        ScimUser createdUser = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        UserAccountStatus userAccountStatus = new UserAccountStatus();
        userAccountStatus.setLocked(true);
        assertThrows(IllegalArgumentException.class, () -> scimUserEndpoints.updateAccountStatus(userAccountStatus, createdUser.getId()));
    }

    @Test
    void testPatchUserStatusWithPasswordExpiryFalse() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.setPassword("password");
        user.addEmail("test@example.org");
        ScimUser createdUser = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        UserAccountStatus userAccountStatus = new UserAccountStatus();
        userAccountStatus.setPasswordChangeRequired(false);
        assertThrows(IllegalArgumentException.class, () -> scimUserEndpoints.updateAccountStatus(userAccountStatus, createdUser.getId()));
    }

    @Test
    void testPatchUserStatusWithPasswordExpiryExternalUser() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.addEmail("test@example.org");
        user.setOrigin("NOT_UAA");
        ScimUser createdUser = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        UserAccountStatus userAccountStatus = new UserAccountStatus();
        userAccountStatus.setPasswordChangeRequired(true);
        assertThrows(IllegalArgumentException.class, () -> scimUserEndpoints.updateAccountStatus(userAccountStatus, createdUser.getId()));
    }

    @Test
    void testCreateUserWithEmailDomainNotAllowedForOriginUaa() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.addEmail("test@example.org");
        user.setOrigin("uaa");
        IdentityProvider ldapProvider = new IdentityProvider().setActive(true).setType(OriginKeys.LDAP).setOriginKey(OriginKeys.LDAP).setConfig(new LdapIdentityProviderDefinition());
        ldapProvider.getConfig().setEmailDomain(Collections.singletonList("example.org"));
        IdentityProvider oidcProvider = new IdentityProvider().setActive(true).setType(OriginKeys.OIDC10).setOriginKey("oidc1").setConfig(new OIDCIdentityProviderDefinition());
        oidcProvider.getConfig().setEmailDomain(Collections.singletonList("example.org"));
        when(mockJdbcIdentityProviderProvisioning.retrieveActive(anyString())).thenReturn(asList(ldapProvider, oidcProvider));

        assertThrowsWithMessageThat(ScimException.class, () -> scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse()),
                containsString("The user account is set up for single sign-on. Please use one of these origin(s) : [ldap, oidc1]")
        );
        verify(mockJdbcIdentityProviderProvisioning).retrieveActive(anyString());
    }

    @Test
    void testCreateUserWithEmailDomainAllowedForOriginNotUaa() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.addEmail("test@example.org");
        user.setOrigin("NOT_UAA");
        IdentityProvider ldapProvider = new IdentityProvider().setActive(true).setType(OriginKeys.LDAP).setOriginKey(OriginKeys.LDAP).setConfig(new LdapIdentityProviderDefinition());
        ldapProvider.getConfig().setEmailDomain(Collections.singletonList("example.org"));
        when(mockJdbcIdentityProviderProvisioning.retrieveActive(anyString())).thenReturn(Collections.singletonList(ldapProvider));

        scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        verify(mockJdbcIdentityProviderProvisioning, times(0)).retrieveActive(anyString());
    }

    @Test
    void testWhenEmailDomainConfiguredForUaaAllowsCreationOfUser() {
        ScimUser user = new ScimUser(null, "uname", "gname", "fname");
        user.addEmail("test@example.org");
        user.setPassword("password");
        user.setOrigin("uaa");
        IdentityProvider uaaProvider = new IdentityProvider().setActive(true).setType(OriginKeys.UAA).setOriginKey(OriginKeys.UAA).setConfig(new UaaIdentityProviderDefinition());
        uaaProvider.getConfig().setEmailDomain(Collections.singletonList("example.org"));
        when(mockJdbcIdentityProviderProvisioning.retrieveActive(anyString())).thenReturn(Collections.singletonList(uaaProvider));

        scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
    }

    @Test
    void testUserWithNoOriginGetsDefaultUaa() {
        ScimUser user = new ScimUser("user1", "joeseph", "Jo", "User");
        user.addEmail("jo@blah.com");
        user.setPassword("password");
        user.setOrigin("");

        ScimUser createdUser = scimUserEndpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());

        assertEquals(OriginKeys.UAA, createdUser.getOrigin());
    }

    @Test
    void testDeleteMfaRegistration() {
        IdentityZoneHolder.get().getConfig().setMfaConfig(new MfaConfig().setEnabled(true).setProviderName("mfaProvider"));
        scimUserEndpoints.deleteMfaRegistration(dale.getId());

        verify(mockJdbcUserGoogleMfaCredentialsProvisioning).delete(dale.getId());
    }

    @Test
    void testDeleteMfaRegistrationUserDoesNotExist() {
        assertThrows(ScimResourceNotFoundException.class, () -> scimUserEndpoints.deleteMfaRegistration("invalidUserId"));
    }

    @Test
    void testDeleteMfaRegistrationNoMfaConfigured() {
        IdentityZoneHolder.get().getConfig().setMfaConfig(new MfaConfig().setEnabled(true).setProviderName("mfaProvider"));
        scimUserEndpoints.deleteMfaRegistration(dale.getId());
    }

    @Test
    void testDeleteMfaRegistrationMfaNotEnabledInZone() {
        IdentityZoneHolder.get().getConfig().setMfaConfig(new MfaConfig().setEnabled(false));
        scimUserEndpoints.deleteMfaRegistration(dale.getId());
    }
}
