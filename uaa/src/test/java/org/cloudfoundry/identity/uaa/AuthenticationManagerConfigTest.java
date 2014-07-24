package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.audit.JdbcFailedLoginCountingAuditService;
import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

public class AuthenticationManagerConfigTest {

    private AnnotationConfigWebApplicationContext webApplicationContext;

    @Before
    public void setUp() throws Exception {
        webApplicationContext = new AnnotationConfigWebApplicationContext();
        webApplicationContext.setEnvironment(new MockEnvironment());
        webApplicationContext.register(MockParentConfiguration.class, AuthenticationManagerConfig.class);
        webApplicationContext.refresh();
    }

    @Test
    public void testConfigurationObject() throws Exception {
        assertThat(webApplicationContext.getBean(Configuration.class), notNullValue());
    }

    @Test
    public void testUaaAuthenticationMgr() throws Exception {
        assertThat(webApplicationContext.getBean("uaaAuthenticationMgr", AuthzAuthenticationManager.class), notNullValue());
    }

    @Test
    public void testAuthzAuthenticationMgr() throws Exception {
        assertThat(webApplicationContext.getBean("authzAuthenticationMgr", AuthzAuthenticationManager.class), notNullValue());
    }

    @org.springframework.context.annotation.Configuration
    public static class MockParentConfiguration {

        @Bean
        public UaaUserDatabase uaaUserDatabase() {
            return Mockito.mock(UaaUserDatabase.class);
        }

        @Bean
        public JdbcFailedLoginCountingAuditService jdbcAuditService() {
            return Mockito.mock(JdbcFailedLoginCountingAuditService.class);
        }

        @Bean
        public LoggingAuditService loggingAuditService() {
            return Mockito.mock(LoggingAuditService.class);
        }
    }
}