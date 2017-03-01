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

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.approval.ApprovalsService;
import org.cloudfoundry.identity.uaa.approval.DescribedApproval;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.account.ProfileController;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
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

import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.DENIED;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.hasValue;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = ProfileControllerTests.ContextConfiguration.class)
public class ProfileControllerTests extends TestClassNullifier {

    public static final String THE_ULTIMATE_APP = "The Ultimate App";

    @Autowired
    WebApplicationContext webApplicationContext;

    @Autowired
    ApprovalsService approvalsService;

    @Autowired
    ClientDetailsService clientDetailsService;

    private MockMvc mockMvc;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

        Map<String, List<DescribedApproval>> approvalsByClientId = new HashMap<String, List<DescribedApproval>>();

        DescribedApproval readApproval = new DescribedApproval();
        readApproval.setUserId("userId");
        readApproval.setClientId("app");
        readApproval.setScope("thing.read");
        readApproval.setStatus(APPROVED);
        readApproval.setDescription("Read your thing resources");

        DescribedApproval writeApproval = new DescribedApproval();
        writeApproval.setUserId("userId");
        writeApproval.setClientId("app");
        writeApproval.setScope("thing.write");
        writeApproval.setStatus(APPROVED);
        writeApproval.setDescription("Write to your thing resources");

        approvalsByClientId.put("app", Arrays.asList(readApproval, writeApproval));

        Mockito.when(approvalsService.getCurrentApprovalsByClientId()).thenReturn(approvalsByClientId);

        BaseClientDetails appClient = new BaseClientDetails("app","thing","thing.read,thing.write","authorization_code", "");
        appClient.addAdditionalInformation(ClientConstants.CLIENT_NAME, THE_ULTIMATE_APP);
        Mockito.when(clientDetailsService.loadClientByClientId("app")).thenReturn(appClient);
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testGetProfile() throws Exception {
        testGetProfile(THE_ULTIMATE_APP);
    }

    @Test
    public void testGetProfileNoAppName() throws Exception {
        BaseClientDetails appClient = new BaseClientDetails("app","thing","thing.read,thing.write","authorization_code", "");
        Mockito.when(clientDetailsService.loadClientByClientId("app")).thenReturn(appClient);
        testGetProfile("app");
    }


    public void testGetProfile(String name) throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("fake-user-id", "username", "email@example.com", OriginKeys.UAA, null, IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(uaaPrincipal, null);

        mockMvc.perform(get("/profile").principal(authentication))
            .andExpect(status().isOk())
            .andExpect(model().attributeExists("clientnames"))
            .andExpect(model().attribute("clientnames", hasKey("app")))
            .andExpect(model().attribute("clientnames", hasValue(is(name))))
            .andExpect(model().attribute("isUaaManagedUser", true))
            .andExpect(model().attribute("approvals", hasKey("app")))
            .andExpect(model().attribute("approvals", hasValue(hasSize(2))))
            .andExpect(content().contentTypeCompatibleWith(TEXT_HTML))
            .andExpect(content().string(containsString("These applications have been granted access to your account.")))
            .andExpect(content().string(containsString("Change Password")))
            .andExpect(content().string(containsString("<h3>"+name)))
            .andExpect(content().string(containsString("Are you sure you want to revoke access to " + name)));
    }


    @Test
    public void testSpecialMessageWhenNoAppsAreAuthorized() throws Exception {
        Map<String, List<DescribedApproval>> approvalsByClientId = new HashMap<String, List<DescribedApproval>>();
        Mockito.when(approvalsService.getCurrentApprovalsByClientId()).thenReturn(approvalsByClientId);

        UaaPrincipal uaaPrincipal = new UaaPrincipal("fake-user-id", "username", "email@example.com", OriginKeys.UAA, null, IdentityZoneHolder.get().getId());
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(uaaPrincipal, null);

        mockMvc.perform(get("/profile").principal(authentication))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("approvals"))
                .andExpect(content().contentTypeCompatibleWith(TEXT_HTML))
                .andExpect(content().string(containsString("You have not yet authorized any third party applications.")));
    }

    @Test
    public void testPasswordLinkHiddenWhenUsersOriginIsNotUaa() throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("fake-user-id", "username", "email@example.com", OriginKeys.LDAP, "dnEntryForLdapUser", IdentityZoneHolder.get().getId());
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

        ArgumentCaptor<List<DescribedApproval>> captor = ArgumentCaptor.forClass((Class)List.class);
        Mockito.verify(approvalsService).updateApprovals(captor.capture());

        DescribedApproval readApproval = captor.getValue().get(0);
        Assert.assertEquals("userId", readApproval.getUserId());
        Assert.assertEquals("app", readApproval.getClientId());
        Assert.assertEquals("thing.read", readApproval.getScope());
        Assert.assertEquals(APPROVED, readApproval.getStatus());

        DescribedApproval writeApproval = captor.getValue().get(1);
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
        ClientDetailsService clientService() {
            return Mockito.mock(ClientDetailsService.class);
        }

        @Bean
        ProfileController profileController(ApprovalsService approvalsService, ClientDetailsService clientDetailsService) {
            return new ProfileController(approvalsService, clientDetailsService);
        }
    }
}
