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

import static org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.oauth.approval.Approval.ApprovalStatus.DENIED;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.hasValue;
import static org.hamcrest.Matchers.not;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Dave Syer
 * 
 */
@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = ProfileControllerTests.ContextConfiguration.class)
public class ProfileControllerTests {

    @Autowired
    WebApplicationContext webApplicationContext;

    @Autowired
    ApprovalsService approvalsService;

    private MockMvc mockMvc;

    @Before
    public void setUp() throws Exception {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

        Map<String, List<UaaApprovalsService.DescribedApproval>> approvalsByClientId = new HashMap<String, List<UaaApprovalsService.DescribedApproval>>();

        UaaApprovalsService.DescribedApproval readApproval = new UaaApprovalsService.DescribedApproval();
        readApproval.setUserId("userId");
        readApproval.setClientId("app");
        readApproval.setScope("thing.read");
        readApproval.setStatus(APPROVED);
        readApproval.setDescription("Read your thing resources");

        UaaApprovalsService.DescribedApproval writeApproval = new UaaApprovalsService.DescribedApproval();
        writeApproval.setUserId("userId");
        writeApproval.setClientId("app");
        writeApproval.setScope("thing.write");
        writeApproval.setStatus(APPROVED);
        writeApproval.setDescription("Write to your thing resources");

        approvalsByClientId.put("app", Arrays.asList(readApproval, writeApproval));

        Mockito.when(approvalsService.getCurrentApprovalsByClientId()).thenReturn(approvalsByClientId);
    }

    @Test
    public void testGetProfile() throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("fake-user-id", "username", "email@example.com", Origin.UAA, null);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(uaaPrincipal, null);

        mockMvc.perform(get("/profile").principal(authentication))
                .andExpect(status().isOk())
                .andExpect(model().attribute("isUaaManagedUser", true))
                .andExpect(model().attribute("approvals", hasKey("app")))
                .andExpect(model().attribute("approvals", hasValue(hasSize(2))))
                .andExpect(content().contentTypeCompatibleWith(TEXT_HTML))
                .andExpect(content().string(containsString("These applications have been granted access to your account.")))
                .andExpect(content().string(containsString("Change Password")));
    }

    @Test
    public void testSpecialMessageWhenNoAppsAreAuthorized() throws Exception {
        Map<String, List<UaaApprovalsService.DescribedApproval>> approvalsByClientId = new HashMap<String, List<UaaApprovalsService.DescribedApproval>>();
        Mockito.when(approvalsService.getCurrentApprovalsByClientId()).thenReturn(approvalsByClientId);

        UaaPrincipal uaaPrincipal = new UaaPrincipal("fake-user-id", "username", "email@example.com", Origin.UAA, null);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(uaaPrincipal, null);

        mockMvc.perform(get("/profile").principal(authentication))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("approvals"))
                .andExpect(content().contentTypeCompatibleWith(TEXT_HTML))
                .andExpect(content().string(containsString("You have not yet authorized any third party applications.")));
    }

    @Test
    public void testPasswordLinkHiddenWhenUsersOriginIsNotUaa() throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("fake-user-id", "username", "email@example.com", Origin.LDAP, "dnEntryForLdapUser");
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(uaaPrincipal, null);

        mockMvc.perform(get("/profile").principal(authentication))
                .andExpect(status().isOk())
                .andExpect(model().attribute("isUaaManagedUser", false))
                .andExpect(content().string(not(containsString("Change Password"))));
    }

    @Test
    public void testUpdateProfile() throws Exception {
        MockHttpServletRequestBuilder post = post("/profile")
                .param("checkedScopes", "app-thing.read")
                .param("update", "")
                .param("clientId", "app");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("profile"));

        ArgumentCaptor<List<UaaApprovalsService.DescribedApproval>> captor = ArgumentCaptor.forClass((Class)List.class);
        Mockito.verify(approvalsService).updateApprovals(captor.capture());

        UaaApprovalsService.DescribedApproval readApproval = captor.getValue().get(0);
        Assert.assertEquals("userId", readApproval.getUserId());
        Assert.assertEquals("app", readApproval.getClientId());
        Assert.assertEquals("thing.read", readApproval.getScope());
        Assert.assertEquals(APPROVED, readApproval.getStatus());

        UaaApprovalsService.DescribedApproval writeApproval = captor.getValue().get(1);
        Assert.assertEquals("userId", writeApproval.getUserId());
        Assert.assertEquals("app", writeApproval.getClientId());
        Assert.assertEquals("thing.write", writeApproval.getScope());
        Assert.assertEquals(DENIED, writeApproval.getStatus());
    }

    @Test
    public void testRevokeApp() throws Exception {
        MockHttpServletRequestBuilder post = post("/profile")
                .param("checkedScopes", "app-resource.read")
                .param("delete", "")
                .param("clientId", "app");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("profile"));

        Mockito.verify(approvalsService).deleteApprovalsForClient("app");
    }

    @Configuration
    @EnableWebMvc
    @Import(ThymeleafConfig.class)
    static class ContextConfiguration extends WebMvcConfigurerAdapter {

        @Override
        public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
            configurer.enable();
        }

        @Bean
        BuildInfo buildInfo() {
            return new BuildInfo();
        }

        @Bean
        ApprovalsService approvalsService() {
            return Mockito.mock(ApprovalsService.class);
        }

        @Bean
        ProfileController profileController(ApprovalsService approvalsService) {
            return new ProfileController(approvalsService);
        }
    }
}
