package org.cloudfoundry.identity.uaa.login;

import io.honeycomb.libhoney.EventFactory;
import io.honeycomb.libhoney.HoneyClient;
import io.honeycomb.libhoney.LibHoney;
import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.account.ResetPasswordService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListener;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.support.ResourcePropertySource;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {ThymeleafAdditional.class, ThymeleafConfig.class, ForcePasswordChangeControllerTest.SpringContextConfiguration.class})
public class ForcePasswordChangeControllerTest  extends TestClassNullifier {

    private MockMvc mockMvc;
    private ResetPasswordService resetPasswordService;
    private ResourcePropertySource resourcePropertySource;
    private AccountSavingAuthenticationSuccessHandler successHandler = mock(AccountSavingAuthenticationSuccessHandler.class);
    private UaaAuthentication authentication;

    @Before
    public void setUp() throws Exception {
        ForcePasswordChangeController controller = new ForcePasswordChangeController();
        resetPasswordService = mock(ResetPasswordService.class);
        controller.setResetPasswordService(resetPasswordService);
        resourcePropertySource = mock(ResourcePropertySource.class);
        controller.setResourcePropertySource(resourcePropertySource);
        successHandler = mock(AccountSavingAuthenticationSuccessHandler.class);
        mockMvc = MockMvcBuilders
            .standaloneSetup(controller)
            .setViewResolvers(getResolver())
            .build();
    }

    @After
    public void clear() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void testForcePasswordChange() throws Exception {
        setAuthentication();
        mockMvc.perform(get("/force_password_change"))
            .andExpect(status().isOk())
            .andExpect(view().name("force_password_change"))
            .andExpect(model().attribute("email", "mail"));
    }

    private void setAuthentication() {
        authentication = mock(UaaAuthentication.class);
        UaaPrincipal principal = mock(UaaPrincipal.class);
        when(authentication.getPrincipal()).thenReturn(principal);
        when(principal.getEmail()).thenReturn("mail");
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @Test
    public void testRedirectToLogInIfPasswordIsNotExpired() throws Exception {
        setAuthentication();
        mockMvc.perform(get("/force_password_change"))
            .andExpect(status().isOk())
            .andExpect(view().name("force_password_change"));
    }


    @Test
    public void testHandleForcePasswordChange() throws Exception {
        setAuthentication();
        mockMvc.perform(
            post("/uaa/force_password_change")
                .param("password","pwd")
                .param("password_confirmation", "pwd")
                .contextPath("/uaa"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/uaa/force_password_change_completed"));
        verify(authentication, times(1)).setAuthenticatedTime(anyLong());
    }

    @Test
    public void testHandleForcePasswordChangeWithRedirect() throws Exception {
        setAuthentication();
        mockMvc.perform(
            post("/force_password_change")
                .param("password","pwd")
                .param("password_confirmation", "pwd"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/force_password_change_completed"));
    }

    @Test
    public void testPasswordAndConfirmAreDifferent() throws Exception {
        setAuthentication();
        when(resourcePropertySource.getProperty("force_password_change.form_error")).thenReturn("Passwords must match and not be empty.");
        mockMvc.perform(
            post("/force_password_change")
                .param("password","pwd")
                .param("password_confirmation", "nopwd"))
            .andExpect(status().isUnprocessableEntity());
    }

    @Configuration
    static class SpringContextConfiguration {
        @Bean
        public EventFactory honeycombEventFactory(@Value("#{T(System).getenv('HONEYCOMB_KEY')}") String honeycombKey,
                                                  @Value("#{T(System).getenv('HONEYCOMB_DATASET')}") String dataset,
                                                  @Value("${testId:-1}") String testId) {
            HoneyClient honeyClient = LibHoney.create(
                    LibHoney.options()
                            .setWriteKey(honeycombKey)
                            .setDataset(dataset)
                            .build()
            );

            if (honeycombKey == null || dataset == null) {
                return honeyClient.buildEventFactory().build();
            }

            String hostName = "";
            try {
                hostName = InetAddress.getLocalHost().getHostName();

            } catch (UnknownHostException e) {
                e.printStackTrace();
            }

            EventFactory.Builder builder = honeyClient.buildEventFactory()
                    .addField("junit", "4")
                    .addField("testId", testId)
                    .addField("cpuCores", Runtime.getRuntime().availableProcessors())
                    .addField("hostname", hostName);

            for (Map.Entry entry : System.getProperties().entrySet()) {
                builder.addField(entry.getKey().toString(), entry.getValue());
            }

            builder.addField("DB", System.getenv().get("DB"));
            builder.addField("SPRING_PROFILE", System.getenv().get("SPRING_PROFILE"));
            builder.addField("JAVA_HOME", System.getenv().get("JAVA_HOME"));

            return builder.build();
        }

        @Bean
        public HoneycombAuditEventTestListener honeycombAuditEventTestListenerAuthenticationFailureLockedEvent(ConfigurableApplicationContext configurableApplicationContext, EventFactory honeycombEventFactory) {
            HoneycombAuditEventTestListener<AuthenticationFailureLockedEvent> listener =
                    HoneycombAuditEventTestListener.forEventClass(AuthenticationFailureLockedEvent.class);
            listener.setHoneycombEventFactory(honeycombEventFactory);
            configurableApplicationContext.addApplicationListener(listener);
            return listener;
        }

        @Bean
        public HoneycombAuditEventTestListener honeycombAuditEventTestListenerIdentityProviderAuthenticationFailureEvent(ConfigurableApplicationContext configurableApplicationContext,EventFactory honeycombEventFactory) {
            HoneycombAuditEventTestListener<IdentityProviderAuthenticationFailureEvent> listener =
                    HoneycombAuditEventTestListener.forEventClass(IdentityProviderAuthenticationFailureEvent.class);
            listener.setHoneycombEventFactory(honeycombEventFactory);
            configurableApplicationContext.addApplicationListener(listener);
            return listener;
        }

        @Bean
        public HoneycombAuditEventTestListener honeycombAuditEventTestListenerMfaAuthenticationFailureEvent(ConfigurableApplicationContext configurableApplicationContext, EventFactory honeycombEventFactory) {
            HoneycombAuditEventTestListener<MfaAuthenticationFailureEvent> listener =
                    HoneycombAuditEventTestListener.forEventClass(MfaAuthenticationFailureEvent.class);
            listener.setHoneycombEventFactory(honeycombEventFactory);
            configurableApplicationContext.addApplicationListener(listener);
            return listener;
        }
    }
}
