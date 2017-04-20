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
package org.cloudfoundry.identity.uaa.oauth.approval;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus;
import org.cloudfoundry.identity.uaa.approval.ApprovalsAdminEndpoints;
import org.cloudfoundry.identity.uaa.approval.JdbcApprovalStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.user.MockUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.DENIED;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ApprovalsAdminEndpointsTests extends JdbcTestBase {
    private UaaTestAccounts testAccounts = null;

    private JdbcApprovalStore dao;

    private UaaUserDatabase userDao = null;

    private UaaUser marissa;

    private ApprovalsAdminEndpoints endpoints;

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void initApprovalsAdminEndpointsTests() {
        testAccounts = UaaTestAccounts.standard(null);
        String userId = testAccounts.getUserWithRandomID().getId();
        userDao = new MockUaaUserDatabase(u -> u.withId(userId).withUsername(testAccounts.getUserName()).withEmail("marissa@test.com").withGivenName("Marissa").withFamilyName("Bloggs"));
        jdbcTemplate = new JdbcTemplate(dataSource);
        marissa = userDao.retrieveUserById(userId);
        assertNotNull(marissa);

        dao = new JdbcApprovalStore(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter),
                        new SimpleSearchQueryConverter());
        endpoints = new ApprovalsAdminEndpoints();
        endpoints.setApprovalStore(dao);
        endpoints.setUaaUserDatabase(userDao);
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        BaseClientDetails details = new BaseClientDetails("c1", "scim,clients", "read,write",
                        "authorization_code, password, implicit, client_credentials", "update");
        details.setAutoApproveScopes(Arrays.asList("true"));
        clientDetailsService.setClientDetailsStore(Collections
                        .singletonMap("c1", details));
        endpoints.setClientDetailsService(clientDetailsService);

        endpoints.setSecurityContextAccessor(mockSecurityContextAccessor(marissa.getUsername(), marissa.getId()));
    }

    private void addApproval(String userName, String clientId, String scope, int expiresIn, ApprovalStatus status) {
        dao.addApproval(new Approval()
            .setUserId(userName)
            .setClientId(clientId)
            .setScope(scope)
            .setExpiresAt(Approval.timeFromNow(expiresIn))
            .setStatus(status));
    }

    private SecurityContextAccessor mockSecurityContextAccessor(String userName, String id) {
        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        when(sca.getUserName()).thenReturn(userName);
        when(sca.getUserId()).thenReturn(id);
        when(sca.isUser()).thenReturn(true);
        return sca;
    }

    @After
    public void cleanupDataSource() throws Exception {
        TestUtils.deleteFrom(dataSource, "authz_approvals");
        TestUtils.deleteFrom(dataSource, "users");
        assertThat(jdbcTemplate.queryForObject("select count(*) from authz_approvals", Integer.class), is(0));
        assertThat(jdbcTemplate.queryForObject("select count(*) from users", Integer.class), is(0));
    }

    @Test
    public void validate_client_id_on_revoke() throws Exception {
        exception.expect(NoSuchClientException.class);
        exception.expectMessage("No client with requested id: invalid_id");
        endpoints.revokeApprovals("invalid_id");
    }

    @Test
    public void validate_client_id_on_update() throws Exception {
        exception.expect(NoSuchClientException.class);
        exception.expectMessage("No client with requested id: invalid_id");
        endpoints.updateClientApprovals("invalid_id", new Approval[0]);
    }


    @Test
    public void canGetApprovals() {
        addApproval(marissa.getId(), "c1", "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "c1", "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "c1", "openid", 6000, APPROVED);

        assertEquals(3, endpoints.getApprovals("user_id pr", 1, 100).size());
        assertEquals(2, endpoints.getApprovals("user_id pr", 1, 2).size());
    }

    @Test
    public void testApprovalsDeserializationIsCaseInsensitive() throws Exception {
        Set<Approval> approvals = new HashSet<>();
        approvals.add(new Approval()
            .setUserId("test-user-id")
            .setClientId("testclientid")
            .setScope("scope")
            .setExpiresAt(new Date())
            .setStatus(ApprovalStatus.APPROVED));
        Set<Approval> deserializedApprovals = JsonUtils.readValue("[{\"userid\":\"test-user-id\",\"clientid\":\"testclientid\",\"scope\":\"scope\",\"status\":\"APPROVED\",\"expiresat\":\"2015-08-25T14:35:42.512Z\",\"lastupdatedat\":\"2015-08-25T14:35:42.512Z\"}]", new TypeReference<Set<Approval>>() {
        });
        assertEquals(approvals, deserializedApprovals);
    }

    @Test
    public void canGetApprovalsWithAutoApproveTrue() {
        // Only get scopes that need approval
        addApproval(marissa.getId(), "c1", "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "c1", "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "c1", "openid", 6000, APPROVED);

        assertEquals(3, endpoints.getApprovals("user_id eq \""+marissa.getId()+"\"", 1, 100).size());

        addApproval(marissa.getId(), "c1", "read", 12000, DENIED);
        addApproval(marissa.getId(), "c1", "write", 6000, APPROVED);

        assertEquals(3, endpoints.getApprovals("user_id eq \""+marissa.getId()+"\"", 1, 100).size());
    }

    @Test
    public void canUpdateApprovals() {
        addApproval(marissa.getId(), "c1", "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "c1", "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "c1", "openid", 6000, APPROVED);

        Approval[] app = new Approval[] {new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("uaa.user")
            .setExpiresAt(Approval.timeFromNow(2000))
            .setStatus(APPROVED),
            new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("dash.user")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(APPROVED),
            new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("openid")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(DENIED),
            new Approval()
                .setUserId(marissa.getId())
                .setClientId("c1")
                .setScope("cloud_controller.read")
                .setExpiresAt(Approval.timeFromNow(2000))
                .setStatus(APPROVED)};
        List<Approval> response = endpoints.updateApprovals(app);
        assertEquals(4, response.size());
        assertTrue(response.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("uaa.user")
            .setExpiresAt(Approval.timeFromNow(2000))
            .setStatus(APPROVED)));
        assertTrue(response.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("dash.user")
            .setExpiresAt(Approval.timeFromNow(2000))
            .setStatus(APPROVED)));
        assertTrue(response.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("openid")
            .setExpiresAt(Approval.timeFromNow(2000))
            .setStatus(DENIED)));
        assertTrue(response.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("cloud_controller.read")
            .setExpiresAt(Approval.timeFromNow(2000))
            .setStatus(APPROVED)));

        List<Approval> updatedApprovals = endpoints.getApprovals("user_id eq \""+marissa.getId()+"\"", 1, 100);
        assertEquals(4, updatedApprovals.size());
        assertTrue(updatedApprovals.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("dash.user")
            .setExpiresAt(Approval.timeFromNow(2000))
            .setStatus(APPROVED)));
        assertTrue(updatedApprovals.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("openid")
            .setExpiresAt(Approval.timeFromNow(2000))
            .setStatus(DENIED)));
        assertTrue(updatedApprovals.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("cloud_controller.read")
            .setExpiresAt(Approval.timeFromNow(2000))
            .setStatus(APPROVED)));
        assertTrue(updatedApprovals.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("uaa.user")
            .setExpiresAt(Approval.timeFromNow(2000))
            .setStatus(APPROVED)));
    }

    public void attemptingToCreateDuplicateApprovalsExtendsValidity() {
        addApproval(marissa.getId(), "c1", "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "c1", "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "c1", "openid", 6000, APPROVED);

        addApproval(marissa.getId(), "c1", "openid", 10000, APPROVED);

        List<Approval> updatedApprovals = endpoints.getApprovals("user_id eq \""+marissa.getId()+"\"", 1, 100);
        assertEquals(3, updatedApprovals.size());
        assertTrue(updatedApprovals.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("uaa.user")
            .setExpiresAt(Approval.timeFromNow(6000))
            .setStatus(APPROVED)));
        assertTrue(updatedApprovals.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("uaa.admin")
            .setExpiresAt(Approval.timeFromNow(12000))
            .setStatus(DENIED)));
        assertTrue(updatedApprovals.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("openid")
            .setExpiresAt(Approval.timeFromNow(10000))
            .setStatus(APPROVED)));
    }

    public void attemptingToCreateAnApprovalWithADifferentStatusUpdatesApproval() {
        addApproval(marissa.getId(), "c1", "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "c1", "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "c1", "openid", 6000, APPROVED);

        addApproval(marissa.getId(), "c1", "openid", 18000, DENIED);

        List<Approval> updatedApprovals = endpoints.getApprovals("user_id eq \""+marissa.getId()+"\"", 1, 100);
        assertEquals(4, updatedApprovals.size());
        assertTrue(updatedApprovals.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("uaa.user")
            .setExpiresAt(Approval.timeFromNow(6000))
            .setStatus(APPROVED)));
        assertTrue(updatedApprovals.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("uaa.admin")
            .setExpiresAt(Approval.timeFromNow(12000))
            .setStatus(DENIED)));
        assertTrue(updatedApprovals.contains(new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("openid")
            .setExpiresAt(Approval.timeFromNow(18000))
            .setStatus(DENIED)));
    }

    @Test(expected = UaaException.class)
    public void userCannotUpdateApprovalsForAnotherUser() {
        addApproval(marissa.getId(), "c1", "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "c1", "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "c1", "openid", 6000, APPROVED);
        endpoints.setSecurityContextAccessor(mockSecurityContextAccessor("vidya", "123456"));
        endpoints.updateApprovals(new Approval[] {new Approval()
            .setUserId(marissa.getId())
            .setClientId("c1")
            .setScope("uaa.user")
            .setExpiresAt(Approval.timeFromNow(2000))
            .setStatus(APPROVED)});
    }

    @Test
    public void canRevokeApprovals() {
        addApproval(marissa.getId(), "c1", "uaa.user", 6000, APPROVED);
        addApproval(marissa.getId(), "c1", "uaa.admin", 12000, DENIED);
        addApproval(marissa.getId(), "c1", "openid", 6000, APPROVED);

        assertEquals(3, endpoints.getApprovals("user_id pr", 1, 100).size());
        assertEquals("ok", endpoints.revokeApprovals("c1").getStatus());
        assertEquals(0, endpoints.getApprovals("user_id pr", 1, 100).size());
    }
}
