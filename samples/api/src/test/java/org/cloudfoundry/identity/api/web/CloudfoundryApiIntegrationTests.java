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
package org.cloudfoundry.identity.api.web;

import static org.junit.Assert.assertNotNull;

import java.net.URL;
import java.util.Date;

import org.cloudfoundry.client.lib.CloudCredentials;
import org.cloudfoundry.client.lib.CloudFoundryClient;
import org.cloudfoundry.client.lib.domain.CloudInfo;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Dave Syer
 */
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.Password.class)
public class CloudfoundryApiIntegrationTests {

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Before
    public void assumeEnvironment() throws Exception {
        // Comment this out to run with -P vcap
        Assume.assumeTrue(!testAccounts.isProfileActive("vcap"));
    }

    @Test
    @Ignore
    public void testClientAccessesProtectedResource() throws Exception {
        OAuth2AccessToken accessToken = context.getAccessToken();
        // add an approval for the scope requested
        HttpHeaders approvalHeaders = new HttpHeaders();
        approvalHeaders.set("Authorization", "bearer " + accessToken.getValue());
        Date oneMinuteAgo = new Date(System.currentTimeMillis() - 60000);
        Date expiresAt = new Date(System.currentTimeMillis() + 60000);
        // ResponseEntity<Approval[]> approvals =
        // serverRunning.getRestTemplate().exchange(
        // serverRunning.getUrl("/uaa/approvals"),
        // HttpMethod.PUT,
        // new HttpEntity<Approval[]>((new Approval[]{new
        // Approval(testAccounts.getUserId(), "app",
        // "cloud_controller.read", expiresAt,
        // ApprovalStatus.APPROVED,oneMinuteAgo), new
        // Approval(testAccounts.getUserId(), "app",
        // "openid", expiresAt, ApprovalStatus.APPROVED,oneMinuteAgo),new
        // Approval(testAccounts.getUserId(), "app",
        // "password.write", expiresAt, ApprovalStatus.APPROVED,oneMinuteAgo)}),
        // approvalHeaders), Approval[].class);
        // assertEquals(HttpStatus.OK, approvals.getStatusCode());

        // System.err.println(accessToken);
        // The client doesn't know how to use an OAuth bearer token
        CloudFoundryClient client = new CloudFoundryClient(
                new CloudCredentials(accessToken),
                new URL("http", "localhost", 8080, "api")
        );
        CloudInfo info = client.getCloudInfo();
        assertNotNull("Wrong cloud info: " + info.getDescription(), info.getUser());
    }
}
