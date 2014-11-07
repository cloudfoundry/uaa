/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpStatus.FOUND;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

public class UaaChangePasswordServiceTest {
    private MockRestServiceServer mockUaaServer;
    private UaaChangePasswordService subject;

    @Before
    public void setUp() throws Exception {
        RestTemplate uaaTemplate = new RestTemplate();
        mockUaaServer = MockRestServiceServer.createServer(uaaTemplate);
        subject = new UaaChangePasswordService(uaaTemplate, "http://uaa.example.com/uaa");
    }

    @Test
    public void testChangePassword() throws Exception {
        mockUaaServer.expect(requestTo("http://uaa.example.com/uaa/password_change"))
                .andExpect(method(POST))
                .andExpect(jsonPath("$.username").value("the user name"))
                .andExpect(jsonPath("$.current_password").value("current password"))
                .andExpect(jsonPath("$.new_password").value("new password"))
                .andRespond(withSuccess("the user name", APPLICATION_JSON));

        subject.changePassword("the user name", "current password", "new password");

        mockUaaServer.verify();
    }
}
