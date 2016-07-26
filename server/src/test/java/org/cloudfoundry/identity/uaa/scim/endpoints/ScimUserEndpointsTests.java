/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.jdbc.DefaultLimitSqlAdapter;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.DisableInternalUserManagementFilter;
import org.cloudfoundry.identity.uaa.scim.InternalUserManagementDisabledException;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.ScimSearchQueryConverter;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
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
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.HttpMediaTypeException;
import org.springframework.web.servlet.View;

import java.util.*;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public class ScimUserEndpointsTests {

    public static final String JDSA_VMWARE_COM = "jd'sa@vmware.com";
    @Rule
    public ExpectedException expected = ExpectedException.none();

    private ScimUser joel;

    private ScimUser dale;

    private ScimUserEndpoints endpoints;

    private ScimGroupEndpoints groupEndpoints;

    private JdbcScimUserProvisioning dao;

    private JdbcScimGroupMembershipManager mm;

    private JdbcApprovalStore am;

    private static EmbeddedDatabase database;
    private PasswordValidator mockPasswordValidator;

    @BeforeClass
    public static void setUpDatabase() throws Exception {
        EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder();
        database = builder.build();
        Flyway flyway = new Flyway();
        flyway.setBaselineVersion(MigrationVersion.fromVersion("1.5.2"));
        flyway.setLocations("classpath:/org/cloudfoundry/identity/uaa/db/hsqldb/");
        flyway.setDataSource(database);
        flyway.migrate();
    }

    @Before
    public void setUp() {
        endpoints = new ScimUserEndpoints();

        IdentityZoneHolder.clear();
        JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
        JdbcPagingListFactory pagingListFactory = new JdbcPagingListFactory(jdbcTemplate, new DefaultLimitSqlAdapter());
        dao = new JdbcScimUserProvisioning(jdbcTemplate, pagingListFactory);
        dao.setPasswordEncoder(NoOpPasswordEncoder.getInstance());

        ScimSearchQueryConverter filterConverter = new ScimSearchQueryConverter();
        Map<String, String> replaceWith = new HashMap<String, String>();
        replaceWith.put("emails\\.value", "email");
        replaceWith.put("groups\\.display", "authorities");
        replaceWith.put("phoneNumbers\\.value", "phoneNumber");
        filterConverter.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));
        dao.setQueryConverter(filterConverter);

        endpoints.setScimUserProvisioning(dao);

        mockPasswordValidator = mock(PasswordValidator.class);
        endpoints.setPasswordValidator(mockPasswordValidator);

        mm = new JdbcScimGroupMembershipManager(jdbcTemplate, pagingListFactory);
        mm.setScimUserProvisioning(dao);
        JdbcScimGroupProvisioning gdao = new JdbcScimGroupProvisioning(jdbcTemplate, pagingListFactory);
        mm.setScimGroupProvisioning(gdao);
        mm.setDefaultUserGroups(Collections.singleton("uaa.user"));
        endpoints.setScimGroupMembershipManager(mm);
        groupEndpoints = new ScimGroupEndpoints(gdao, mm);

        joel = new ScimUser(null, "jdsa", "Joel", "D'sa");
        joel.addEmail(JDSA_VMWARE_COM);
        dale = new ScimUser(null, "olds", "Dale", "Olds");
        dale.addEmail("olds@vmware.com");
        joel = dao.createUser(joel, "password");
        dale = dao.createUser(dale, "password");

        Map<Class<? extends Exception>, HttpStatus> map = new HashMap<Class<? extends Exception>, HttpStatus>();
        map.put(IllegalArgumentException.class, HttpStatus.BAD_REQUEST);
        map.put(UnsupportedOperationException.class, HttpStatus.BAD_REQUEST);
        map.put(BadSqlGrammarException.class, HttpStatus.BAD_REQUEST);
        map.put(DataIntegrityViolationException.class, HttpStatus.BAD_REQUEST);
        map.put(HttpMessageConversionException.class, HttpStatus.BAD_REQUEST);
        map.put(HttpMediaTypeException.class, HttpStatus.BAD_REQUEST);
        endpoints.setStatuses(map);

        am = new JdbcApprovalStore(jdbcTemplate, pagingListFactory, new ScimSearchQueryConverter());
        endpoints.setApprovalStore(am);
    }

    @AfterClass
    public static void tearDown() throws Exception {
        if (database != null) {
            database.shutdown();
        }
    }

    @After
    public void cleanUp() throws Exception {
        TestUtils.deleteFrom(database, "group_membership", "users", "groups", "authz_approvals");
        IdentityZoneHolder.clear();
    }

    private void validateUserGroups(ScimUser user, String... gnm) {
        Set<String> expectedAuthorities = new HashSet<String>();
        expectedAuthorities.addAll(Arrays.asList(gnm));
        expectedAuthorities.add("uaa.user");
        assertNotNull(user.getGroups());
        Log logger = LogFactory.getLog(getClass());
        logger.debug("user's groups: " + user.getGroups() + ", expecting: " + expectedAuthorities);
        assertEquals(expectedAuthorities.size(), user.getGroups().size());
        for (ScimUser.Group g : user.getGroups()) {
            assertTrue(expectedAuthorities.contains(g.getDisplay()));
        }
    }

    @Test
    public void groupsIsSyncedCorrectlyOnCreate() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail("dsyer@vmware.com");
        user.setGroups(Arrays.asList(new ScimUser.Group(null, "test1")));
        ScimUser created = endpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        validateUserGroups(created, "uaa.user");
    }

    @Test
    public void groupsIsSyncedCorrectlyOnUpdate() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail("dsyer@vmware.com");
        ScimUser created = endpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        validateUserGroups(created, "uaa.user");

        created.setGroups(Arrays.asList(new ScimUser.Group(null, "test1")));
        ScimUser updated = endpoints.updateUser(created, created.getId(), "*", new MockHttpServletRequest(), new MockHttpServletResponse());
        validateUserGroups(updated, "uaa.user");
    }

    @Test
    public void groupsIsSyncedCorrectlyOnGet() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail("dsyer@vmware.com");
        ScimUser created = endpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());

        validateUserGroups(created, "uaa.user");

        ScimGroup g = new ScimGroup(null,"test1",IdentityZoneHolder.get().getId());
        g.setMembers(Arrays.asList(new ScimGroupMember(created.getId())));
        g = groupEndpoints.createGroup(g, new MockHttpServletResponse());

        validateUserGroups(endpoints.getUser(created.getId(), new MockHttpServletResponse()), "test1");
    }

    @Test
    public void approvalsIsSyncedCorrectlyOnCreate() {
        ScimUser user = new ScimUser(null, "vidya", "Vidya", "V");
        user.addEmail("vidya@vmware.com");
        user.setApprovals(Collections.singleton(new Approval()
            .setUserId("vidya")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(6000))
            .setStatus(Approval.ApprovalStatus.APPROVED)));
        ScimUser created = endpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());

        assertNotNull(created.getApprovals());
        assertEquals(1, created.getApprovals().size());
    }

    @Test
    public void approvalsIsSyncedCorrectlyOnUpdate() {


        ScimUser user = new ScimUser(null, "vidya", "Vidya", "V");
        user.addEmail("vidya@vmware.com");
        user.setApprovals(Collections.singleton(new Approval()
            .setUserId("vidya")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(6000))
            .setStatus(Approval.ApprovalStatus.APPROVED)));
        ScimUser created = endpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        am.addApproval(new Approval()
            .setUserId(created.getId())
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(6000))
            .setStatus(Approval.ApprovalStatus.APPROVED));
        am.addApproval(new Approval()
            .setUserId(created.getId())
            .setClientId("c1")
            .setScope("s2")
            .setExpiresAt(Approval.timeFromNow(6000))
            .setStatus(Approval.ApprovalStatus.DENIED));

        created.setApprovals(Collections.singleton(new Approval()
            .setUserId("vidya")
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(6000))
            .setStatus(Approval.ApprovalStatus.APPROVED)));
        ScimUser updated = endpoints.updateUser(created, created.getId(), "*", new MockHttpServletRequest(), new MockHttpServletResponse());
        assertEquals(2, updated.getApprovals().size());
    }

    @Test
    public void approvalsIsSyncedCorrectlyOnGet() {
        assertEquals(0, endpoints.getUser(joel.getId(), new MockHttpServletResponse()).getApprovals().size());

        am.addApproval(new Approval()
            .setUserId(joel.getId())
            .setClientId("c1")
            .setScope("s1")
            .setExpiresAt(Approval.timeFromNow(6000))
            .setStatus(Approval.ApprovalStatus.APPROVED));
        am.addApproval(new Approval()
            .setUserId(joel.getId())
            .setClientId("c1")
            .setScope("s2")
            .setExpiresAt(Approval.timeFromNow(6000))
            .setStatus(Approval.ApprovalStatus.DENIED));

        assertEquals(2, endpoints.getUser(joel.getId(), new MockHttpServletResponse()).getApprovals().size());
    }

    @Test
    public void createUser_whenPasswordIsInvalid_throwsException() {
        doThrow(new InvalidPasswordException("whaddup")).when(mockPasswordValidator).validate(anyString());
        ScimUserProvisioning mockDao = mock(ScimUserProvisioning.class);
        endpoints.setScimUserProvisioning(mockDao);
        when(mockDao.createUser(any(ScimUser.class), anyString())).thenReturn(new ScimUser());

        ScimUser user = new ScimUser();
        user.setPassword("some bad password");

        try {
            endpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        } catch (InvalidPasswordException e) {
            assertEquals(e.getStatus(), HttpStatus.BAD_REQUEST);
            assertEquals(e.getMessage(), "whaddup");
        }

        verify(mockPasswordValidator).validate("some bad password");
    }


    @Test
    public void createUser_withNullPassword_createsUserWithRandomPassword() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail("dsyer@vmware.com");
        ScimUser created = endpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        assertNull("A newly created user revealed its password", created.getPassword());
        JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
        String password = jdbcTemplate.queryForObject("select password from users where id=?", String.class,
                created.getId());
        // Generated password...
        assertNotNull(password);
    }

    @Test
    public void createUser_withNullPassword_doesNotInvokePasswordValidator() {
        ScimUserProvisioning mockDao = mock(ScimUserProvisioning.class);
        endpoints.setScimUserProvisioning(mockDao);
        when(mockDao.createUser(any(ScimUser.class), anyString())).thenReturn(new ScimUser());

        endpoints.createUser(new ScimUser(), new MockHttpServletRequest(), new MockHttpServletResponse());
        verify(mockPasswordValidator, never()).validate(anyString());
    }

    @Test
    public void userWithNoEmailNotAllowed() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        try {
            endpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
            fail("Expected InvalidScimResourceException");
        } catch (InvalidScimResourceException e) {
            // expected
            String message = e.getMessage();
            assertTrue("Wrong message: " + message, message.contains("email"));
        }
        JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
        int count = jdbcTemplate.queryForObject("select count(*) from users where userName=?", new Object[] {"dave"}, Integer.class);
        assertEquals(0, count);
    }

    @Test(expected = InternalUserManagementDisabledException.class)
    public void create_uaa_user_when_internal_user_management_is_disabled() {
        create_user_when_internal_user_management_is_disabled(OriginKeys.UAA);
    }

    @Test
    public void create_ldap_user_when_internal_user_management_is_disabled() {
        create_user_when_internal_user_management_is_disabled(OriginKeys.LDAP);
    }

    public void create_user_when_internal_user_management_is_disabled(String origin) {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail(new RandomValueStringGenerator().generate() + "@test.org");
        user.setOrigin(origin);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(DisableInternalUserManagementFilter.DISABLE_INTERNAL_USER_MANAGEMENT, true);
        endpoints.createUser(user, request, new MockHttpServletResponse());
    }

    @Test
    public void testHandleExceptionWithConstraintViolation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        endpoints.setMessageConverters(new HttpMessageConverter<?>[]{new ExceptionReportHttpMessageConverter()});
        View view = endpoints.handleException(new DataIntegrityViolationException("foo"), request);
        ConvertingExceptionView converted = (ConvertingExceptionView) view;
        converted.render(Collections.<String, Object>emptyMap(), request, response);
        String body = response.getContentAsString();
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
        // System.err.println(body);
        assertTrue("Wrong body: " + body, body.contains("message\":\"foo"));
    }

    @Test
    public void testHandleExceptionWithBadFieldName() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        endpoints.setMessageConverters(new HttpMessageConverter<?>[]{new ExceptionReportHttpMessageConverter()});
        View view = endpoints.handleException(new HttpMessageConversionException("foo"), request);
        ConvertingExceptionView converted = (ConvertingExceptionView) view;
        converted.render(Collections.<String, Object>emptyMap(), request, response);
        String body = response.getContentAsString();
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
        // System.err.println(body);
        assertTrue("Wrong body: " + body, body.contains("message\":\"foo"));
    }

    @Test
    public void userCanInitializePassword() {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail("dsyer@vmware.com");
        ReflectionTestUtils.setField(user, "password", "foo");
        ScimUser created = endpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());
        assertNull("A newly created user revealed its password", created.getPassword());
        JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
        String password = jdbcTemplate.queryForObject("select password from users where id=?", String.class,
                created.getId());
        assertEquals("foo", password);
    }

    @Test
    public void deleteIsAllowedWithCorrectVersionInEtag() {
        ScimUser exGuy = new ScimUser(null, "deleteme", "Expendable", "Guy");
        exGuy.addEmail("exguy@imonlyheretobedeleted.com");
        exGuy = dao.createUser(exGuy, "exguyspassword");
        endpoints.deleteUser(exGuy.getId(), Integer.toString(exGuy.getMeta().getVersion()),
                             new MockHttpServletRequest(), new MockHttpServletResponse());
    }

    @Test
    public void deleteIsAllowedWithQuotedEtag() {
        ScimUser exGuy = new ScimUser(null, "deleteme", "Expendable", "Guy");
        exGuy.addEmail("exguy@imonlyheretobedeleted.com");
        exGuy = dao.createUser(exGuy, "exguyspassword");
        endpoints.deleteUser(exGuy.getId(), "\"*", new MockHttpServletRequest(), new MockHttpServletResponse());
    }

    @Test(expected = InternalUserManagementDisabledException.class)
    public void deleteIs_Not_Allowed_For_UAA_When_InternalUserManagement_Is_Disabled() {
        test_Delete_When_InternalUserManagement_Is_Disabled(OriginKeys.UAA);
    }

    @Test
    public void deleteIs_Allowed_For_LDAP_When_InternalUserManagement_Is_Disabled() {
        test_Delete_When_InternalUserManagement_Is_Disabled(OriginKeys.LDAP);
    }

    public void test_Delete_When_InternalUserManagement_Is_Disabled(String origin) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(DisableInternalUserManagementFilter.DISABLE_INTERNAL_USER_MANAGEMENT, true);
        ScimUser exGuy = new ScimUser(null, "deleteme", "Expendable", "Guy");
        exGuy.setOrigin(origin);
        exGuy.addEmail("exguy@imonlyheretobedeleted.com");
        exGuy = dao.createUser(exGuy, "exguyspassword");
        endpoints.deleteUser(exGuy.getId(), "\"*", request, new MockHttpServletResponse());
    }


    @Test(expected = OptimisticLockingFailureException.class)
    public void deleteIsNotAllowedWithWrongVersionInEtag() {
        ScimUser exGuy = new ScimUser(null, "deleteme2", "Expendable", "Guy");
        exGuy.addEmail("exguy2@imonlyheretobedeleted.com");
        exGuy = dao.createUser(exGuy, "exguyspassword");
        endpoints.deleteUser(exGuy.getId(), Integer.toString(exGuy.getMeta().getVersion() + 1),
                             new MockHttpServletRequest(), new MockHttpServletResponse());
    }

    @Test
    public void deleteIsAllowedWithNullEtag() {
        ScimUser exGuy = new ScimUser(null, "deleteme3", "Expendable", "Guy");
        exGuy.addEmail("exguy3@imonlyheretobedeleted.com");
        exGuy = dao.createUser(exGuy, "exguyspassword");
        endpoints.deleteUser(exGuy.getId(), null, new MockHttpServletRequest(), new MockHttpServletResponse());
    }

    @Test
    public void deleteUserUpdatesGroupMembership() {
        ScimUser exGuy = new ScimUser(null, "deleteme3", "Expendable", "Guy");
        exGuy.addEmail("exguy3@imonlyheretobedeleted.com");
        exGuy = dao.createUser(exGuy, "exguyspassword");

        ScimGroup g = new ScimGroup(null,"test1",IdentityZoneHolder.get().getId());
        g.setMembers(Arrays.asList(new ScimGroupMember(exGuy.getId())));
        g = groupEndpoints.createGroup(g, new MockHttpServletResponse());
        validateGroupMembers(g, exGuy.getId(), true);

        endpoints.deleteUser(exGuy.getId(), "*", new MockHttpServletRequest(), new MockHttpServletResponse());
        validateGroupMembers(groupEndpoints.getGroup(g.getId(), new MockHttpServletResponse()), exGuy.getId(), false);
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
    public void testFindAllIds() {
        SearchResults<?> results = endpoints.findUsers("id", "id pr", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
    }

    @Test
    public void testFindPageOfIds() {
        SearchResults<?> results = endpoints.findUsers("id", "id pr", null, "ascending", 1, 1);
        assertEquals(2, results.getTotalResults());
        assertEquals(1, results.getResources().size());
    }

    @Test
    public void testFindMultiplePagesOfIds() {
        dao.setPageSize(1);
        SearchResults<?> results = endpoints.findUsers("id", "id pr", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertEquals(2, results.getResources().size());
    }

    @Test
    public void testFindWhenStartGreaterThanTotal() {
        SearchResults<?> results = endpoints.findUsers("id", "id pr", null, "ascending", 3, 100);
        assertEquals(2, results.getTotalResults());
        assertEquals(0, results.getResources().size());
    }

    @Test
    public void testFindAllNames() {
        SearchResults<?> results = endpoints.findUsers("userName", "id pr", null, "ascending", 1, 100);
        Collection<Object> values = getSetFromMaps(results.getResources(), "userName");
        assertTrue(values.contains("olds"));
    }

    @Test
    public void testFindAllNamesWithStartIndex() {
        SearchResults<?> results = endpoints.findUsers("name", "id pr", null, "ascending", 1, 100);
        assertEquals(2, results.getResources().size());

        results = endpoints.findUsers("name", "id pr", null, "ascending", 2, 100);
        assertEquals(1, results.getResources().size());

        results = endpoints.findUsers("name", "id pr", null, "ascending", 3, 100);
        assertEquals(0, results.getResources().size());
    }

    @Test
    public void testFindAllEmails() {
        SearchResults<?> results = endpoints.findUsers("emails.value", "id pr", null, "ascending", 1, 100);
        Collection<Object> values = getSetFromMaps(results.getResources(), "emails.value");
        assertTrue(values.contains(Arrays.asList("olds@vmware.com")));
    }

    @Test
    public void testFindAllAttributes() {
        endpoints.findUsers("id", "id pr", null, "ascending", 1, 100);
        SearchResults<Map<String, Object>> familyNames = (SearchResults<Map<String, Object>>) endpoints.findUsers("familyName", "id pr", "familyName", "ascending", 1, 100);
        SearchResults<Map<String, Object>> givenNames = (SearchResults<Map<String, Object>>) endpoints.findUsers("givenName", "id pr", "givenName", "ascending", 1, 100);
        endpoints.findUsers("phoneNumbers", "id pr", null, "ascending", 1, 100);
        endpoints.findUsers("externalId", "id pr", null, "ascending", 1, 100);
        endpoints.findUsers("meta.version", "id pr", null, "ascending", 1, 100);
        endpoints.findUsers("meta.created", "id pr", null, "ascending", 1, 100);
        endpoints.findUsers("meta.lastModified", "id pr", null, "ascending", 1, 100);
        endpoints.findUsers("zoneId", "id pr", null, "ascending", 1, 100);

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
    public void testFindNonExistingAttributes() {
        String nonExistingAttribute = "blabla";
        List<Map<String, Object>> resources = (List<Map<String, Object>>) endpoints.findUsers(nonExistingAttribute, "id pr", null, "ascending", 1, 100).getResources();
        for (Map<String, Object> resource : resources) {
            assertNull(resource.get(nonExistingAttribute));
        }
    }

    @Test
    public void testFindUsersGroupsSyncedByDefault() throws Exception {
        ScimGroupMembershipManager mockgroupMembershipManager = mock(ScimGroupMembershipManager.class);
        endpoints.setScimGroupMembershipManager(mockgroupMembershipManager);

        endpoints.findUsers("", "id pr", null, "ascending", 1, 100);
        verify(mockgroupMembershipManager, atLeastOnce()).getGroupsWithMember(anyString(), anyBoolean());

        endpoints.setScimGroupMembershipManager(mm);
    }

    @Test
    public void testFindUsersGroupsSyncedIfIncluded() throws Exception {
        ScimGroupMembershipManager mockgroupMembershipManager = mock(ScimGroupMembershipManager.class);
        endpoints.setScimGroupMembershipManager(mockgroupMembershipManager);

        endpoints.findUsers("groups", "id pr", null, "ascending", 1, 100);
        verify(mockgroupMembershipManager, atLeastOnce()).getGroupsWithMember(anyString(), anyBoolean());

        endpoints.setScimGroupMembershipManager(mm);
    }

    @Test
    public void testFindUsersGroupsNotSyncedIfNotIncluded() throws Exception {
        ScimGroupMembershipManager mockgroupMembershipManager = mock(ScimGroupMembershipManager.class);
        endpoints.setScimGroupMembershipManager(mockgroupMembershipManager);

        endpoints.findUsers("emails.value", "id pr", null, "ascending", 1, 100);
        verifyZeroInteractions(mockgroupMembershipManager);

        endpoints.setScimGroupMembershipManager(mm);
    }

    @Test
    public void testFindUsersApprovalsSyncedByDefault() throws Exception {
        ApprovalStore mockApprovalStore = mock(ApprovalStore.class);
        endpoints.setApprovalStore(mockApprovalStore);

        endpoints.findUsers("", "id pr", null, "ascending", 1, 100);
        verify(mockApprovalStore, atLeastOnce()).getApprovals(anyString());

        endpoints.setApprovalStore(am);
    }

    @Test
    public void testFindUsersApprovalsSyncedIfIncluded() throws Exception {
        ApprovalStore mockApprovalStore = mock(ApprovalStore.class);
        endpoints.setApprovalStore(mockApprovalStore);

        endpoints.findUsers("approvals", "id pr", null, "ascending", 1, 100);
        verify(mockApprovalStore, atLeastOnce()).getApprovals(anyString());

        endpoints.setApprovalStore(am);
    }

    @Test
    public void testFindUsersApprovalsNotSyncedIfNotIncluded() throws Exception {
        ApprovalStore mockApprovalStore = mock(ApprovalStore.class);
        endpoints.setApprovalStore(mockApprovalStore);

        endpoints.findUsers("emails.value", "id pr", null, "ascending", 1, 100);
        verifyZeroInteractions(mockApprovalStore);

        endpoints.setApprovalStore(am);
    }

    @Test
    public void testInvalidFilterExpression() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Invalid filter"));
        SearchResults<?> results = endpoints.findUsers("id", "userName qq 'd'", null, "ascending", 1, 100);
        assertEquals(0, results.getTotalResults());
    }

    @Test
    public void testValidFilterExpression() {
        SearchResults<?> results = endpoints.findUsers("id", "userName eq \"d\"", "created", "ascending", 1, 100);
        assertEquals(0, results.getTotalResults());
    }

    @Test
    public void testInvalidOrderByExpression() {
        expected.expect(ScimException.class);
        expected.expectMessage(containsString("Invalid filter"));
        SearchResults<?> results = endpoints.findUsers("id", "userName eq \"d\"", "created,unknown", "ascending", 1, 100);
        assertEquals(0, results.getTotalResults());
    }

    @Test
    public void testValidOrderByExpression() {
        endpoints.findUsers("id", "userName eq \"d\"", "1,created", "ascending", 1, 100);
        endpoints.findUsers("id", "userName eq \"d\"", "1,2", "ascending", 1, 100);
        endpoints.findUsers("id", "userName eq \"d\"", "username,created", "ascending", 1, 100);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testFindIdsByUserName() {
        SearchResults<?> results = endpoints.findUsers("id", "userName eq \"jdsa\"", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertEquals(1, results.getSchemas().size()); // System.err.println(results.getValues());
        assertEquals(joel.getId(), ((Map<String, Object>) results.getResources().iterator().next()).get("id"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testFindIdsByEmailApostrophe() {
        SearchResults<?> results = endpoints.findUsers("id", "emails.value eq \"" + JDSA_VMWARE_COM + "\"", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertEquals(1, results.getSchemas().size()); // System.err.println(results.getValues());
        assertEquals(joel.getId(), ((Map<String, Object>) results.getResources().iterator().next()).get("id"));
    }

    @Test
    public void testFindIdsByUserNameContains() {
        SearchResults<?> results = endpoints.findUsers("id", "userName co \"d\"", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    public void testFindIdsByUserNameStartWith() {
        SearchResults<?> results = endpoints.findUsers("id", "userName sw \"j\"", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    public void testFindIdsByEmailContains() {
        SearchResults<?> results = endpoints.findUsers("id", "emails.value sw \"j\"", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    public void testFindIdsByEmailContainsWithEmptyResult() {
        SearchResults<?> results = endpoints.findUsers("id", "emails.value sw \"z\"", null, "ascending", 1, 100);
        assertEquals(0, results.getTotalResults());
    }

    @Test
    public void testFindIdsWithBooleanExpression() {
        SearchResults<?> results = endpoints.findUsers("id", "userName co \"d\" and id pr", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    public void testFindIdsWithBooleanExpressionIvolvingEmails() {
        SearchResults<?> results = endpoints.findUsers("id",
                "userName co \"d\" and emails.value co \"vmware\"", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    public void testCreateIncludesETagHeader() throws Exception {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail("dave@vmware.com");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        endpoints.createUser(user, new MockHttpServletRequest(), httpServletResponse);
        assertEquals("\"0\"", httpServletResponse.getHeader("ETag"));
    }

    @Test
    public void testGetIncludesETagHeader() throws Exception {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail("dave@vmware.com");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        endpoints.getUser(joel.getId(), httpServletResponse);
        assertEquals("\"0\"", httpServletResponse.getHeader("ETag"));
    }

    @Test
    public void testUpdateIncludesETagHeader() throws Exception {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail("dave@vmware.com");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        endpoints.updateUser(joel, joel.getId(), "*", new MockHttpServletRequest(), httpServletResponse);
        assertEquals("\"1\"", httpServletResponse.getHeader("ETag"));
    }

    @Test(expected = InternalUserManagementDisabledException.class)
    public void test_update_when_internal_user_management_is_disabled_for_uaa() throws Exception {
        update_when_internal_user_management_is_disabled(OriginKeys.UAA);
    }

    @Test
    public void test_update_when_internal_user_management_is_disabled_for_ldap() throws Exception {
        update_when_internal_user_management_is_disabled(OriginKeys.LDAP);
    }

    public void update_when_internal_user_management_is_disabled(String origin) throws Exception {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail("dave@vmware.com");
        user.setOrigin(origin);

        user = endpoints.createUser(user, new MockHttpServletRequest(), new MockHttpServletResponse());

        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(DisableInternalUserManagementFilter.DISABLE_INTERNAL_USER_MANAGEMENT, true);
        endpoints.updateUser(user, user.getId(), "*", request, httpServletResponse);
    }

    @Test
    public void testVerifyIncludesETagHeader() throws Exception {
        ScimUser user = new ScimUser(null, "dave", "David", "Syer");
        user.addEmail("dave@vmware.com");
        MockHttpServletResponse httpServletResponse = new MockHttpServletResponse();
        endpoints.verifyUser("" + joel.getId(), "*", httpServletResponse);
        assertEquals("\"0\"", httpServletResponse.getHeader("ETag"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void legacyTestFindIdsByUserName() {
        SearchResults<?> results = endpoints.findUsers("id", "userName eq 'jdsa'", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertEquals(1, results.getSchemas().size()); // System.err.println(results.getValues());
        assertEquals(joel.getId(), ((Map<String, Object>) results.getResources().iterator().next()).get("id"));
    }

    @Test
    public void legacyTestFindIdsByUserNameContains() {
        SearchResults<?> results = endpoints.findUsers("id", "userName co 'd'", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    public void legacyTestFindIdsByUserNameStartWith() {
        SearchResults<?> results = endpoints.findUsers("id", "userName sw 'j'", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    public void legacyTestFindIdsByEmailContains() {
        SearchResults<?> results = endpoints.findUsers("id", "emails.value sw 'j'", null, "ascending", 1, 100);
        assertEquals(1, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    public void legacyTestFindIdsByEmailContainsWithEmptyResult() {
        SearchResults<?> results = endpoints.findUsers("id", "emails.value sw 'z'", null, "ascending", 1, 100);
        assertEquals(0, results.getTotalResults());
    }

    @Test
    public void legacyTestFindIdsWithBooleanExpression() {
        SearchResults<?> results = endpoints.findUsers("id", "userName co 'd' and id pr", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    public void legacyTestFindIdsWithBooleanExpressionIvolvingEmails() {
        SearchResults<?> results = endpoints.findUsers("id",
                "userName co 'd' and emails.value co 'vmware'", null, "ascending", 1, 100);
        assertEquals(2, results.getTotalResults());
        assertTrue("Couldn't find id: " + results.getResources(), getSetFromMaps(results.getResources(), "id")
                .contains(joel.getId()));
    }

    @Test
    public void zeroUsersInADifferentIdentityZone() {
        IdentityZone zone = new IdentityZone();
        zone.setId("not-uaa");
        zone.setSubdomain("not-uaa");
        zone.setName("not-uaa");
        zone.setDescription("not-uaa");
        IdentityZoneHolder.set(zone);
        SearchResults<?> results = endpoints.findUsers("id",
                "id pr", null, "ascending", 1, 100);
        assertEquals(0, results.getTotalResults());
    }

    @SuppressWarnings("unchecked")
    private Collection<Object> getSetFromMaps(Collection<?> resources, String key) {
        Collection<Object> result = new ArrayList<Object>();
        for (Object map : resources) {
            result.add(((Map<String, Object>) map).get(key));
        }
        return result;
    }
}
