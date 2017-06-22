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
import org.cloudfoundry.identity.uaa.account.ProfileController;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.approval.DescribedApproval;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
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
import static org.mockito.ArgumentMatchers.anyString;
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
    public static final String USER_ID = "userId";

    @Autowired
    WebApplicationContext webApplicationContext;

    @Autowired
    ClientDetailsService clientDetailsService;

    @Autowired
    ApprovalStore approvalStore;

    private MockMvc mockMvc;
    private List<DescribedApproval> allDescApprovals;
    private List<Approval> allApprovals;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

        Mockito.reset(approvalStore);
        Mockito.reset(clientDetailsService);
        Map<String, List<DescribedApproval>> approvalsByClientId = new HashMap<>();

        DescribedApproval otherApproval = new DescribedApproval();
        otherApproval.setUserId(USER_ID);
        otherApproval.setClientId("other-client");
        otherApproval.setScope("thing.read");
        otherApproval.setStatus(APPROVED);
        otherApproval.setDescription("Read your thing resources");

        DescribedApproval readApproval = new DescribedApproval();
        readApproval.setUserId(USER_ID);
        readApproval.setClientId("app");
        readApproval.setScope("thing.read");
        readApproval.setStatus(APPROVED);
        readApproval.setDescription("Read your thing resources");

        DescribedApproval writeApproval = new DescribedApproval();
        writeApproval.setUserId(USER_ID);
        writeApproval.setClientId("app");
        writeApproval.setScope("thing.write");
        writeApproval.setStatus(APPROVED);
        writeApproval.setDescription("Write to your thing resources");

        allDescApprovals = Arrays.asList(otherApproval, readApproval, writeApproval);
        allApprovals = new LinkedList<>(allDescApprovals);
        approvalsByClientId.put("app", allDescApprovals);

        Mockito.when(approvalStore.getApprovalsForUser(anyString(), anyString())).thenReturn(allApprovals);

        BaseClientDetails appClient = new BaseClientDetails("app","thing","thing.read,thing.write","authorization_code", "");
        appClient.addAdditionalInformation(ClientConstants.CLIENT_NAME, THE_ULTIMATE_APP);
        Mockito.when(clientDetailsService.loadClientByClientId("app")).thenReturn(appClient);

        BaseClientDetails otherClient = new BaseClientDetails("other-client","thing","thing.read,thing.write","authorization_code", "");
        otherClient.addAdditionalInformation(ClientConstants.CLIENT_NAME, THE_ULTIMATE_APP);
        Mockito.when(clientDetailsService.loadClientByClientId("other-client")).thenReturn(otherClient);
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
        Mockito.when(approvalStore.getApprovalsForUser(anyString(), anyString())).thenReturn(Collections.emptyList());

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

        ArgumentCaptor<String> args = ArgumentCaptor.forClass(String.class);
        Mockito.verify(approvalStore,Mockito.times(2)).revokeApprovalsForClientAndUser(args.capture(), args.capture(), args.capture());
        Assert.assertEquals(6, args.getAllValues().size());

        ArgumentCaptor<DescribedApproval> captor = ArgumentCaptor.forClass(DescribedApproval.class);
        Mockito.verify(approvalStore, Mockito.times(2)).addApproval(captor.capture(), anyString());

        Assert.assertEquals(2, captor.getAllValues().size());

        DescribedApproval readApproval = captor.getAllValues().get(0);
        Assert.assertEquals(USER_ID, readApproval.getUserId());
        Assert.assertEquals("app", readApproval.getClientId());
        Assert.assertEquals("thing.read", readApproval.getScope());
        Assert.assertEquals(APPROVED, readApproval.getStatus());

        DescribedApproval writeApproval = captor.getAllValues().get(1);
        Assert.assertEquals(USER_ID, writeApproval.getUserId());
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

        String zoneId = IdentityZoneHolder.get().getId();
        Mockito.verify(approvalStore, Mockito.times(1)).revokeApprovalsForClientAndUser("app", USER_ID, zoneId);
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
        ApprovalStore approvalsService() {
            return Mockito.mock(ApprovalStore.class);
        }

        @Bean
        ClientServicesExtension clientService() {
            return Mockito.mock(ClientServicesExtension.class);
        }

        @Bean
        SecurityContextAccessor securityContextAccessor() {
            SecurityContextAccessor result = Mockito.mock(SecurityContextAccessor.class);
            Mockito.when(result.isUser()).thenReturn(true);
            Mockito.when(result.getUserId()).thenReturn(USER_ID);
            return result;
        }

        @Bean
        ProfileController profileController(ApprovalStore approvalsService,
                                            ClientServicesExtension clientDetailsService,
                                            SecurityContextAccessor securityContextAccessor) {
            return new ProfileController(approvalsService, clientDetailsService, securityContextAccessor);
        }
    }
}
