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
package org.cloudfoundry.identity.uaa.login;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasKey;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.PUT;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.DescribedApproval;
import org.cloudfoundry.identity.uaa.approval.RestUaaApprovalsService;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class RestUaaApprovalsServiceTest {

    private MockRestServiceServer mockUaaServer;
    private RestUaaApprovalsService approvalsService;

    @Before
    public void setUp() throws Exception {
        RestTemplate restTemplate = new RestTemplate();
        mockUaaServer = MockRestServiceServer.createServer(restTemplate);

        approvalsService = new RestUaaApprovalsService(restTemplate, "http://uaa.example.com/uaa/approvals");
    }

    @Test
    public void testRetrievingApprovals() throws Exception {
        mockUaaServer.expect(requestTo("http://uaa.example.com/uaa/approvals"))
                .andExpect(method(GET))
                .andExpect(header("Accept", containsString(APPLICATION_JSON_VALUE)))
                .andRespond(withSuccess("[{\"userId\":\"abc-def-ghi\", \"clientId\":\"app\", \"scope\":\"scim.userids\", \"status\":\"APPROVED\", \"expiresAt\":\"2014-05-17T15:17:52.310Z\", \"lastUpdatedAt\":\"2014-04-17T15:17:52.317Z\"}," +
                        "{\"userId\":\"abc-def-ghi\", \"clientId\":\"app\", \"scope\":\"cloud_controller.read\", \"status\":\"APPROVED\", \"expiresAt\":\"2014-05-17T15:17:52.310Z\", \"lastUpdatedAt\":\"2014-04-17T15:17:52.311Z\"}," +
                        "{\"userId\":\"abc-def-ghi\", \"clientId\":\"app\", \"scope\":\"cloud_controller.write\", \"status\":\"APPROVED\", \"expiresAt\":\"2014-05-17T15:17:52.310Z\", \"lastUpdatedAt\":\"2014-04-17T15:17:52.313Z\"}," +
                        "{\"userId\":\"abc-def-ghi\", \"clientId\":\"app\", \"scope\":\"password.write\", \"status\":\"DENIED\", \"expiresAt\":\"2014-05-17T15:17:52.310Z\", \"lastUpdatedAt\":\"2014-04-17T15:17:52.316Z\"}]", APPLICATION_JSON));

        Map<String, List<DescribedApproval>> approvalsByClientId = approvalsService.getCurrentApprovalsByClientId();
        Assert.assertThat(approvalsByClientId, hasKey("app"));
        
        List<DescribedApproval> describedApprovals = approvalsByClientId.get("app");
        Assert.assertEquals(4, describedApprovals.size());

        DescribedApproval cloudControllerReadApproval = describedApprovals.get(0);
        Assert.assertEquals("abc-def-ghi", cloudControllerReadApproval.getUserId());
        Assert.assertEquals("app", cloudControllerReadApproval.getClientId());
        Assert.assertEquals("cloud_controller.read", cloudControllerReadApproval.getScope());
        Assert.assertEquals(Approval.ApprovalStatus.APPROVED, cloudControllerReadApproval.getStatus());
        Assert.assertEquals("Access your 'cloud_controller' resources with scope 'read'", cloudControllerReadApproval.getDescription());

        DescribedApproval passwordWriteApproval = describedApprovals.get(2);
        Assert.assertEquals("password.write", passwordWriteApproval.getScope());
        Assert.assertEquals(Approval.ApprovalStatus.DENIED, passwordWriteApproval.getStatus());

        mockUaaServer.verify();
    }

    @Test
    public void testUpdatingApprovals() throws Exception {
        mockUaaServer.expect(requestTo("http://uaa.example.com/uaa/approvals"))
                .andExpect(method(PUT))
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].clientId").value("app"))
                .andExpect(jsonPath("$[0].userId").value("user-id"))
                .andExpect(jsonPath("$[0].scope").value("thing.write"))
                .andExpect(jsonPath("$[0].status").value("APPROVED"))
                .andRespond(withSuccess());

        List<DescribedApproval> approvals = new ArrayList<DescribedApproval>();
        DescribedApproval approval = new DescribedApproval();
        approval.setClientId("app");
        approval.setUserId("user-id");
        approval.setScope("thing.write");
        approval.setStatus(Approval.ApprovalStatus.APPROVED);
        approval.setDescription("Write to your thing resources");
        approvals.add(approval);

        approvalsService.updateApprovals(approvals);

        mockUaaServer.verify();
    }

    @Test
    public void testRevokingApprovals() throws Exception {
        mockUaaServer.expect(requestTo("http://uaa.example.com/uaa/approvals?clientId=abc-def"))
                .andExpect(method(DELETE))
                .andRespond(withSuccess("", APPLICATION_JSON));

        approvalsService.deleteApprovalsForClient("abc-def");

        mockUaaServer.verify();
    }
}
