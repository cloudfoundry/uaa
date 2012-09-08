package org.cloudfoundry.identity.uaa.scim.groups;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.sql.DataSource;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = { "", "test,postgresql", "hsqldb" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcScimGroupMembershipManagerTests {

    Log logger = LogFactory.getLog(getClass());

    @Autowired
    private DataSource dataSource;

    private JdbcTemplate template;

    private JdbcScimGroupMembershipManager dao;

    private static final String addMemberSqlFormat = "insert into group_membership (group_id, member_id, member_type, authorities) values ('%s', '%s', '%s', '%s')";

    @Before
    public void createDatasource() {

        template = new JdbcTemplate(dataSource);

        dao = new JdbcScimGroupMembershipManager(template);
        addMember("g1", "m1", "USER", "READ");
        addMember("g1", "g2", "GROUP", "READ");
        addMember("g3", "m2", "USER", "READ,WRITE");

        validateCount(3);
    }

    private void addMember (String gId, String mId, String mType, String authorities) {
        template.execute(String.format(addMemberSqlFormat, gId, mId, mType, authorities));
    }

    private void validateCount(int expected) {
        int existingMemberCount = template.queryForInt("select count(*) from group_membership");
        assertEquals(expected, existingMemberCount);
    }

    @After
    public void cleanupDataSource() throws Exception{
        TestUtils.deleteFrom(dataSource, "group_membership");
        validateCount(0);
    }

    @Test
    public void canAddMember() throws Exception {
        ScimGroupMember m1 = new ScimGroupMember("m3", null, null);
        ScimGroupMember m2 = dao.addMember("g2", m1);
        logger.debug(m2);
        validateCount(4);
        assertEquals(ScimGroupMember.Type.USER, m2.getType());
        assertEquals(ScimGroup.GROUP_MEMBER, m2.getAuthorities());
        assertEquals("m3", m2.getId());
    }

    @Test
    public void canGetMembers() throws Exception {
        List<ScimGroupMember> members = dao.getMembers("g1");
        logger.debug(members);
        assertEquals(2, members.size());
    }

    @Test
    public void canGetAdminMembers() {
        addMember("g1", "m3", "USER", "READ,WRITE");
        assertEquals(1, dao.getAdminMembers("g1").size());
        assertTrue(dao.getAdminMembers("g1").contains(new ScimGroupMember("m3")));

        assertEquals(1, dao.getAdminMembers("g3").size());
        assertTrue(dao.getAdminMembers("g3").contains(new ScimGroupMember("m2")));

        assertEquals(0, dao.getAdminMembers("g2").size());
    }

    @Test
    public void canGetMemberById() throws Exception {
        ScimGroupMember m = dao.getMemberById("g3", "m2");
        assertEquals(ScimGroupMember.Type.USER, m.getType());
        assertEquals(ScimGroup.GROUP_ADMIN, m.getAuthorities());
    }

    @Test
    public void canUpdateMember() throws Exception {
        ScimGroupMember m1 = new ScimGroupMember("m1", ScimGroupMember.Type.USER, ScimGroup.GROUP_ADMIN);
        ScimGroupMember m2 = dao.updateMember("g1", m1);
        assertEquals(ScimGroup.GROUP_ADMIN, m2.getAuthorities());
        assertNotSame(m1, m2);
    }

    @Test
    public void canUpdateOrAddMembers() {
        ScimGroupMember g2 = new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, ScimGroup.GROUP_ADMIN);
        ScimGroupMember m3 = new ScimGroupMember("m3", ScimGroupMember.Type.USER, ScimGroup.GROUP_MEMBER);
        List<ScimGroupMember> members = dao.updateOrAddMembers("g1", Arrays.asList(g2, m3));
        assertEquals(2, members.size());
        logger.debug(members);
        assertTrue(members.contains(new ScimGroupMember("g2", ScimGroupMember.Type.GROUP, null)));
        assertFalse(members.contains(new ScimGroupMember("m1", ScimGroupMember.Type.USER, null)));
    }

    @Test
    public void canRemoveMemberById() throws Exception {
        dao.removeMemberById("g1", "m1");
        validateCount(2);
        try {
            dao.getMemberById("g1", "m1");
            fail("member should not exist");
        } catch (MemberNotFoundException ex) {

        }
    }

    @Test
    public void canRemoveAllMembers() {
        dao.removeMembers("g1");
        validateCount(1);
        try {
            dao.getMemberById("g1", "m1");
            fail("member should not exist");
        } catch (MemberNotFoundException ex) {

        }
    }
}
