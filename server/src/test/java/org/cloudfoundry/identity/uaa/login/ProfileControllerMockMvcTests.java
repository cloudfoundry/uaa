package org.cloudfoundry.identity.uaa.login;

import jakarta.annotation.PostConstruct;
import org.cloudfoundry.identity.uaa.account.ProfileController;
import org.cloudfoundry.identity.uaa.approval.Approval;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.approval.DescribedApproval;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.util.beans.TestBuildInfo;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.DefaultServletHandlerConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.APPROVED;
import static org.cloudfoundry.identity.uaa.approval.Approval.ApprovalStatus.DENIED;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.hasValue;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(PollutionPreventionExtension.class)
@WebAppConfiguration
@SpringJUnitConfig(classes = ProfileControllerMockMvcTests.ContextConfiguration.class)
class ProfileControllerMockMvcTests {

    @EnableWebMvc
    @Import(ThymeleafConfig.class)
    static class ContextConfiguration implements WebMvcConfigurer {

        @Autowired
        private RequestMappingHandlerAdapter requestMappingHandlerAdapter;

        @PostConstruct
        public void init() {
            requestMappingHandlerAdapter.setIgnoreDefaultModelOnRedirect(false);
        }

        @Override
        public void configureDefaultServletHandling(DefaultServletHandlerConfigurer configurer) {
            configurer.enable();
        }

        @Bean
        BuildInfo buildInfo() {
            return new TestBuildInfo();
        }

        @Bean
        ApprovalStore approvalsService() {
            return mock(ApprovalStore.class);
        }

        @Bean
        MultitenantClientServices clientService() {
            return mock(MultitenantClientServices.class);
        }

        @Bean
        IdentityZoneManager identityZoneManager() {
            return mock(IdentityZoneManager.class);
        }

        @Bean
        SecurityContextAccessor securityContextAccessor() {
            SecurityContextAccessor result = mock(SecurityContextAccessor.class);
            when(result.isUser()).thenReturn(true);
            when(result.getUserId()).thenReturn(USER_ID);
            return result;
        }

        @Bean
        ProfileController profileController(ApprovalStore approvalsService,
                                            MultitenantClientServices clientDetailsService,
                                            SecurityContextAccessor securityContextAccessor,
                                            IdentityZoneManager identityZoneManager) {
            return new ProfileController(approvalsService, clientDetailsService, securityContextAccessor, identityZoneManager);
        }
    }

    private static final String THE_ULTIMATE_APP = "The Ultimate App";
    private static final String USER_ID = "userId";

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private MultitenantClientServices clientDetailsService;

    @Autowired
    private ApprovalStore approvalStore;

    @Autowired
    private IdentityZoneManager identityZoneManager;

    private MockMvc mockMvc;

    private String currentIdentityZoneId;

    @BeforeEach
    void setUp() {
        currentIdentityZoneId = "currentIdentityZoneId-" + UUID.randomUUID().toString();
        when(identityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentIdentityZoneId);
        SecurityContextHolder.clearContext();
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

        Mockito.reset(approvalStore);
        Mockito.reset(clientDetailsService);

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

        List<DescribedApproval> allDescApprovals = Arrays.asList(otherApproval, readApproval, writeApproval);
        List<Approval> allApprovals = new LinkedList<>(allDescApprovals);

        when(approvalStore.getApprovalsForUser(anyString(), eq(currentIdentityZoneId))).thenReturn(allApprovals);

        UaaClientDetails appClient = new UaaClientDetails("app", "thing", "thing.read,thing.write", GRANT_TYPE_AUTHORIZATION_CODE, "");
        appClient.addAdditionalInformation(ClientConstants.CLIENT_NAME, THE_ULTIMATE_APP);
        when(clientDetailsService.loadClientByClientId("app", currentIdentityZoneId)).thenReturn(appClient);

        UaaClientDetails otherClient = new UaaClientDetails("other-client", "thing", "thing.read,thing.write", GRANT_TYPE_AUTHORIZATION_CODE, "");
        otherClient.addAdditionalInformation(ClientConstants.CLIENT_NAME, THE_ULTIMATE_APP);
        when(clientDetailsService.loadClientByClientId("other-client", currentIdentityZoneId)).thenReturn(otherClient);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void getProfile() throws Exception {
        getProfile(mockMvc, THE_ULTIMATE_APP, currentIdentityZoneId);
    }

    @Test
    void getProfileNoAppName() throws Exception {
        UaaClientDetails appClient = new UaaClientDetails("app", "thing", "thing.read,thing.write", GRANT_TYPE_AUTHORIZATION_CODE, "");
        when(clientDetailsService.loadClientByClientId("app", currentIdentityZoneId)).thenReturn(appClient);
        getProfile(mockMvc, "app", currentIdentityZoneId);
    }

    @Test
    void specialMessageWhenNoAppsAreAuthorized() throws Exception {
        when(approvalStore.getApprovalsForUser(anyString(), eq(currentIdentityZoneId))).thenReturn(Collections.emptyList());

        UaaPrincipal uaaPrincipal = new UaaPrincipal("fake-user-id", "username", "email@example.com", OriginKeys.UAA, null, currentIdentityZoneId);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(uaaPrincipal, null);

        mockMvc.perform(get("/profile").principal(authentication))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("approvals"))
                .andExpect(content().contentTypeCompatibleWith(TEXT_HTML))
                .andExpect(content().string(containsString("You have not yet authorized any third party applications.")));
    }

    @Test
    void passwordLinkHiddenWhenUsersOriginIsNotUaa() throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("fake-user-id", "username", "email@example.com", OriginKeys.LDAP, "dnEntryForLdapUser", currentIdentityZoneId);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(uaaPrincipal, null);

        mockMvc.perform(get("/profile").principal(authentication))
                .andExpect(status().isOk())
                .andExpect(model().attribute("isUaaManagedUser", false))
                .andExpect(model().attributeDoesNotExist("email"))
                .andExpect(content().string(not(containsString("Change Password"))));
    }

    @Test
    void updateProfile() throws Exception {
        MockHttpServletRequestBuilder post = post("/profile")
                .param("checkedScopes", "app-thing.read")
                .param("update", "")
                .param("clientId", "app");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("profile"));

        ArgumentCaptor<String> args = ArgumentCaptor.forClass(String.class);
        Mockito.verify(approvalStore, Mockito.times(2)).revokeApprovalsForClientAndUser(args.capture(), args.capture(), args.capture());
        assertThat(args.getAllValues()).hasSize(6);

        ArgumentCaptor<DescribedApproval> captor = ArgumentCaptor.forClass(DescribedApproval.class);
        Mockito.verify(approvalStore, Mockito.times(2)).addApproval(captor.capture(), eq(currentIdentityZoneId));

        assertThat(captor.getAllValues()).hasSize(2);

        DescribedApproval readApproval = captor.getAllValues().getFirst();
        assertThat(readApproval.getUserId()).isEqualTo(USER_ID);
        assertThat(readApproval.getClientId()).isEqualTo("app");
        assertThat(readApproval.getScope()).isEqualTo("thing.read");
        assertThat(readApproval.getStatus()).isEqualTo(APPROVED);

        DescribedApproval writeApproval = captor.getAllValues().get(1);
        assertThat(writeApproval.getUserId()).isEqualTo(USER_ID);
        assertThat(writeApproval.getClientId()).isEqualTo("app");
        assertThat(writeApproval.getScope()).isEqualTo("thing.write");
        assertThat(writeApproval.getStatus()).isEqualTo(DENIED);
    }

    @Test
    void revokeApp() throws Exception {
        MockHttpServletRequestBuilder post = post("/profile")
                .param("checkedScopes", "app-resource.read")
                .param("delete", "")
                .param("clientId", "app");

        mockMvc.perform(post)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("profile"));

        Mockito.verify(approvalStore, Mockito.times(1)).revokeApprovalsForClientAndUser("app", USER_ID, currentIdentityZoneId);
    }

    private static void getProfile(final MockMvc mockMvc, final String name, final String currentIdentityZoneId) throws Exception {
        UaaPrincipal uaaPrincipal = new UaaPrincipal("fake-user-id", "username", "email@example.com", OriginKeys.UAA, null, currentIdentityZoneId);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(uaaPrincipal, null);

        mockMvc.perform(get("/profile").principal(authentication))
                .andExpect(status().isOk())
                .andExpect(model().attributeExists("clientnames"))
                .andExpect(model().attribute("clientnames", hasKey("app")))
                .andExpect(model().attribute("clientnames", hasValue(is(name))))
                .andExpect(model().attribute("isUaaManagedUser", true))
                .andExpect(model().attribute("email", "email@example.com"))
                .andExpect(model().attribute("approvals", hasKey("app")))
                .andExpect(model().attribute("approvals", hasValue(hasSize(2))))
                .andExpect(content().contentTypeCompatibleWith(TEXT_HTML))
                .andExpect(content().string(containsString("These applications have been granted access to your account.")))
                .andExpect(content().string(containsString("Change Password")))
                .andExpect(content().string(containsString("<h3>" + name)))
                .andExpect(content().string(containsString("Are you sure you want to revoke access to " + name)));
    }

}
