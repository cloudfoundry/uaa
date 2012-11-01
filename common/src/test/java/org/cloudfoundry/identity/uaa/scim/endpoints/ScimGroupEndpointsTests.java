package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.error.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.impl.JdbcScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.impl.JdbcScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.impl.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.impl.NullPasswordValidator;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.servlet.View;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class ScimGroupEndpointsTests {

	Log logger = LogFactory.getLog(getClass());

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcScimGroupProvisioning dao;

	private JdbcScimUserProvisioning udao;

	private JdbcScimGroupMembershipManager mm;

	private ScimGroupEndpoints endpoints;

	private ScimUserEndpoints userEndpoints;

	private List<String> groupIds;

	private static final String SQL_INJECTION_FIELDS = "displayName,version,created,lastModified";

	@Rule
	public ExpectedException expectedEx = ExpectedException.none();

	@Before
	public void setup() {
		template = new JdbcTemplate(dataSource);
		dao = new JdbcScimGroupProvisioning(template);
		udao = new JdbcScimUserProvisioning(template);
		udao.setPasswordValidator(new NullPasswordValidator());
		mm = new JdbcScimGroupMembershipManager(template);
		mm.setScimGroupProvisioning(dao);
		mm.setScimUserProvisioning(udao);
		mm.setDefaultUserGroups(Collections.singleton("uaa.user"));

		endpoints = new ScimGroupEndpoints(dao, mm);
		userEndpoints = new ScimUserEndpoints();
		userEndpoints.setScimUserProvisioning(udao);
		userEndpoints.setScimGroupMembershipManager(mm);

		groupIds = new ArrayList<String>();
		groupIds.add(addGroup("uaa.resource", Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER),
															   createMember(ScimGroupMember.Type.GROUP, ScimGroup.GROUP_MEMBER),
															   createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)))
		);
		groupIds.add(addGroup("uaa.admin", Collections.<ScimGroupMember>emptyList()));
		groupIds.add(addGroup("uaa.none", Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER),
															   createMember(ScimGroupMember.Type.GROUP, ScimGroup.GROUP_ADMIN)))
		);

	}

	@After
	public void cleanup() throws Exception {
		TestUtils.deleteFrom(dataSource, "users");
		TestUtils.deleteFrom(dataSource, "groups");
		TestUtils.deleteFrom(dataSource, "group_membership");
	}

	private String addGroup(String name, List<ScimGroupMember> m) {
		ScimGroup g = new ScimGroup("", name);
		g = dao.createGroup(g);
		for (ScimGroupMember member : m) {
			mm.addMember(g.getId(), member);
		}
		return g.getId();
	}

	private ScimGroupMember createMember(ScimGroupMember.Type t, List<ScimGroup.Authority> a) {
		String id = UUID.randomUUID().toString();
		if (t == ScimGroupMember.Type.USER) {
			id = userEndpoints.createUser(TestUtils.scimUserInstance(id)).getId();
		} else {
			id = dao.createGroup(new ScimGroup("", id)).getId();
		}
		return new ScimGroupMember(id, t, a);
	}

	private void validateSearchResults (SearchResults<?> results, int expectedSize) {
		assertNotNull(results);
		assertNotNull(results.getResources());
		assertEquals(expectedSize, results.getResources().size());
	}

	private void validateGroup(ScimGroup g, String expectedName, int expectedMemberCount) {
		assertNotNull(g);
		assertNotNull(g.getId());
		assertNotNull(g.getVersion());
		assertEquals(expectedName, g.getDisplayName());
		assertNotNull(g.getMembers());
		assertEquals(expectedMemberCount, g.getMembers().size());
	}

	private void validateUserGroups (String id, String... gnm) {
		ScimUser user = userEndpoints.getUser(id);
		Set<String> expectedAuthorities = new HashSet<String>();
		expectedAuthorities.addAll(Arrays.asList(gnm));
		expectedAuthorities.add("uaa.user");
		assertNotNull(user.getGroups());
		logger.debug("user's groups: " + user.getGroups() + ", expecting: " + expectedAuthorities);
		assertEquals(expectedAuthorities.size(), user.getGroups().size());
		for (ScimUser.Group g : user.getGroups()) {
			assertTrue(expectedAuthorities.contains(g.getDisplay()));
		}
	}

	@Test
	public void testListGroups() throws Exception {
		validateSearchResults(endpoints.listGroups("id,displayName", "id pr", "created", "ascending", 1, 100), 6);
	}

	@Test
	public void testListGroupsWithNameEqFilter() {
		validateSearchResults(endpoints.listGroups("id,displayName", "displayName eq 'uaa.user'", "created", "ascending", 1, 100), 1);
	}

	@Test
	public void testListGroupsWithNameCoFilter() {
		validateSearchResults(endpoints.listGroups("id,displayName", "displayName co 'admin'", "created", "ascending", 1, 100), 1);
	}

	@Test
	public void testListGroupsWithInvalidFilterFails() {
		expectedEx.expect(ScimException.class);
		expectedEx.expectMessage("Invalid filter expression");
		endpoints.listGroups("id,displayName", "displayName cr 'admin'", "created", "ascending", 1, 100);
	}

	@Test
	public void testListGroupsWithInvalidAttributesFails() {
		expectedEx.expect(ScimException.class);
		expectedEx.expectMessage("Invalid attributes");
		endpoints.listGroups("id,display", "displayName co 'admin'", "created", "ascending", 1, 100);
	}

	@Test
	public void testListGroupsWithNullAttributes() {
		validateSearchResults(endpoints.listGroups(null, "displayName co 'admin'", "created", "ascending", 1, 100), 1);
	}

	@Test
	public void testSqlInjectionAttackFailsCorrectly() {
		expectedEx.expect(ScimException.class);
		expectedEx.expectMessage("Invalid filter expression");
		endpoints.listGroups("id,display", "displayName='something'; select " + SQL_INJECTION_FIELDS
				+ " from groups where displayName='something'", "created", "ascending", 1, 100);
	}

	@Test
	public void testGetGroup() throws Exception {
		ScimGroup g = endpoints.getGroup(groupIds.get(0));
		validateGroup(g, "uaa.resource", 3);
	}

	@Test
	public void testGetNonExistentGroupFails() {
		expectedEx.expect(ScimResourceNotFoundException.class);
		endpoints.getGroup("wrongid");
	}

	@Test
	public void testCreateGroup() throws Exception {
		ScimGroup g = new ScimGroup("", "clients.read");
		g.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		ScimGroup g1 = endpoints.createGroup(g);
		validateGroup(g1, "clients.read", 1);
		validateUserGroups(g.getMembers().get(0).getMemberId(), "clients.read");
	}

	@Test
	public void testCreateExistingGroupFails() {
		ScimGroup g = new ScimGroup("", "clients.read");
		g.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		ScimGroup g1 = endpoints.createGroup(g);

		expectedEx.expect(ScimResourceAlreadyExistsException.class);
		ScimGroup g2 = endpoints.createGroup(g);
	}

	@Test
	public void testCreateGroupWithInvalidMemberFails() {
		ScimGroup g = new ScimGroup("", "clients.read");
		g.setMembers(Arrays.asList(new ScimGroupMember("non-existent id", ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));

		try {
			ScimGroup g1 = endpoints.createGroup(g);
			fail("must have thrown exception");
		} catch (InvalidScimResourceException ex) {
			// ensure that the group was not created
			validateSearchResults(endpoints.listGroups("id", "displayName eq 'clients.read'", "id", "ASC", 1, 100), 0);
		}
	}

	@Test
	public void testUpdateGroup() throws Exception {
		ScimGroup g = new ScimGroup("", "clients.read");
		g.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g = endpoints.createGroup(g);
		validateUserGroups(g.getMembers().get(0).getMemberId(), "clients.read");

		g.setDisplayName("superadmin");
		g.getMembers().get(0).setAuthorities(ScimGroup.GROUP_MEMBER);
		ScimGroup g1 = endpoints.updateGroup(g, g.getId(), "*");

		validateGroup(g1, "superadmin", 1);
		assertEquals(ScimGroup.GROUP_MEMBER, g1.getMembers().get(0).getAuthorities());
		validateUserGroups(g.getMembers().get(0).getMemberId(), "superadmin");
	}

	@Test
	public void testUpdateNonUniqueDisplayNameFails() {
		ScimGroup g1 = new ScimGroup("", "clients.read");
		g1.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g1 = endpoints.createGroup(g1);

		ScimGroup g2 = new ScimGroup("", "clients.write");
		g2.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g2 = endpoints.createGroup(g2);

		g1.setDisplayName("clients.write");
		expectedEx.expect(InvalidScimResourceException.class);
		endpoints.updateGroup(g1, g1.getId(), "*");
	}

	@Test
	public void testUpdateWithInvalidMemberFails() {
		ScimGroup g1 = new ScimGroup("", "clients.read");
		g1.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g1 = endpoints.createGroup(g1);

		g1.setMembers(Arrays.asList(new ScimGroupMember("non-existent id", ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g1.setDisplayName("clients.write");

		try {
			endpoints.updateGroup(g1, g1.getId(), "*");
			fail("must have thrown exception");
		} catch (ScimException ex) {
			// ensure that displayName was not updated
			g1 = endpoints.getGroup(g1.getId());
			validateGroup(g1, "clients.read", 0);
			validateSearchResults(endpoints.listGroups("id", "displayName eq 'clients.write'", "id", "ASC", 1, 100), 0);
		}
	}

	@Test
	public void testUpdateInvalidVersionFails() {
		ScimGroup g1 = new ScimGroup("", "clients.read");
		g1.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g1 = endpoints.createGroup(g1);

		g1.setDisplayName("clients.write");

		expectedEx.expect(ScimException.class);
		expectedEx.expectMessage("Invalid version");
		endpoints.updateGroup(g1, g1.getId(), "version");
	}

	@Test
	public void testUpdateGroupWithNullEtagFails() {
		ScimGroup g1 = new ScimGroup("", "clients.read");
		g1.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g1 = endpoints.createGroup(g1);

		g1.setDisplayName("clients.write");

		expectedEx.expect(ScimException.class);
		expectedEx.expectMessage("Missing If-Match");
		endpoints.updateGroup(g1, g1.getId(), null);
	}

	@Test
	public void testUpdateWithQuotedVersionSucceeds() {
		ScimGroup g1 = new ScimGroup("", "clients.read");
		g1.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g1 = endpoints.createGroup(g1);

		g1.setDisplayName("clients.write");

		endpoints.updateGroup(g1, g1.getId(), "\"*");

		endpoints.updateGroup(g1, g1.getId(), "*\"");
	}

	@Test
	public void testUpdateWrongVersionFails() {
		ScimGroup g1 = new ScimGroup("", "clients.read");
		g1.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g1 = endpoints.createGroup(g1);

		g1.setDisplayName("clients.write");

		expectedEx.expect(ScimException.class);
		endpoints.updateGroup(g1, g1.getId(), String.valueOf(g1.getVersion() + 23));
	}

	@Test
	public void testDeleteGroup() throws Exception {
		ScimGroup g = new ScimGroup("", "clients.read");
		g.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g = endpoints.createGroup(g);
		validateUserGroups(g.getMembers().get(0).getMemberId(), "clients.read");

		g = endpoints.deleteGroup(g.getId(), "*");
		try {
			endpoints.getGroup(g.getId());
			fail("group should not exist");
		} catch (ScimResourceNotFoundException ex) { }
		logger.debug("deleted group: " + g);
		validateUserGroups(g.getMembers().get(0).getMemberId(), "uaa.user");
	}

	@Test
	public void testDeleteWrongVersionFails() {
		ScimGroup g = new ScimGroup("", "clients.read");
		g.setMembers(Arrays.asList(createMember(ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN)));
		g = endpoints.createGroup(g);

		expectedEx.expect(ScimException.class);
		endpoints.deleteGroup(g.getId(),String.valueOf(g.getVersion() + 3) );
	}

	@Test
	public void testDeleteNonExistentGroupFails() {
		expectedEx.expect(ScimResourceNotFoundException.class);
		endpoints.deleteGroup("some id", "*");
	}

	@Test
	public void testExceptionHandler() {
		Map<Class<? extends Exception>, HttpStatus> map = new HashMap<Class<? extends Exception>, HttpStatus>();
		map.put(IllegalArgumentException.class, HttpStatus.BAD_REQUEST);
		map.put(UnsupportedOperationException.class, HttpStatus.BAD_REQUEST);
		map.put(BadSqlGrammarException.class, HttpStatus.BAD_REQUEST);
		endpoints.setStatuses(map);
		HttpMessageConverter[] converters = {new ExceptionReportHttpMessageConverter()};
		endpoints.setMessageConverters(converters);

		MockHttpServletRequest request = new MockHttpServletRequest();
		validateView(endpoints.handleException(new ScimResourceNotFoundException(""), request), HttpStatus.NOT_FOUND);
		validateView(endpoints.handleException(new UnsupportedOperationException(""), request), HttpStatus.BAD_REQUEST);
		validateView(endpoints.handleException(new BadSqlGrammarException("", "", null), request), HttpStatus.BAD_REQUEST);
		validateView(endpoints.handleException(new IllegalArgumentException(""), request), HttpStatus.BAD_REQUEST);
		validateView(endpoints.handleException(new DataIntegrityViolationException(""), request), HttpStatus.BAD_REQUEST);
	}

	private void validateView (View view, HttpStatus status) {
		MockHttpServletResponse response = new MockHttpServletResponse();
		try {
			view.render(new HashMap<String, Object>(), new MockHttpServletRequest(), response);
			assertNotNull(response.getContentAsString());
		} catch (Exception e) {
			fail("view should render correct status and body");
		}
		assertEquals(status.value(), response.getStatus());
	}
}
