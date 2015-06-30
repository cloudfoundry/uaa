package org.cloudfoundry.identity.uaa.mock.config;

import org.cloudfoundry.identity.uaa.authentication.manager.PeriodLockoutPolicy;
import org.cloudfoundry.identity.uaa.config.LockoutPolicy;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.web.context.support.XmlWebApplicationContext;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

public class LockoutPolicyTests {

    private static final String DEFAULT_UAA_LOCKOUT_POLICY = "defaultUaaLockoutPolicy";
    private static final String GLOBAL_LOCKOUT_POLICY = "globalPeriodLockoutPolicy";

    private XmlWebApplicationContext webApplicationContext;
    private MockEnvironment environment;

    @Before
    public void setUp() {
        webApplicationContext = new XmlWebApplicationContext();
        environment = new MockEnvironment();
        webApplicationContext.setEnvironment(environment);
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
    }

    @After
    public void tearDown() throws Exception {
        webApplicationContext.destroy();
        webApplicationContext = null;
        environment = null;
    }

    @Test
    public void testAuthenticationPolicyDefaults() throws Exception {
        webApplicationContext.refresh();
        PeriodLockoutPolicy globalPeriodLockoutPolicy = (PeriodLockoutPolicy) webApplicationContext.getBean(GLOBAL_LOCKOUT_POLICY);
        LockoutPolicy globalLockoutPolicy = globalPeriodLockoutPolicy.getLockoutPolicy();
        assertThat(globalLockoutPolicy.getLockoutAfterFailures(), equalTo(5));
        assertThat(globalLockoutPolicy.getCountFailuresWithin(), equalTo(3600));
        assertThat(globalLockoutPolicy.getLockoutPeriodSeconds(), equalTo(300));

        PeriodLockoutPolicy periodLockoutPolicy = (PeriodLockoutPolicy) webApplicationContext.getBean(DEFAULT_UAA_LOCKOUT_POLICY);
        LockoutPolicy lockoutPolicy = periodLockoutPolicy.getLockoutPolicy();
        assertThat(lockoutPolicy.getLockoutAfterFailures(), equalTo(5));
        assertThat(lockoutPolicy.getCountFailuresWithin(), equalTo(3600));
        assertThat(lockoutPolicy.getLockoutPeriodSeconds(), equalTo(300));
    }

    @Test
    public void testAuthenticationPolicyConfig() throws Exception {
        environment.setProperty("authentication.policy.lockoutAfterFailures", "10");
        environment.setProperty("authentication.policy.countFailuresWithinSeconds", "7200");
        environment.setProperty("authentication.policy.lockoutPeriodSeconds", "600");
        webApplicationContext.refresh();
        PeriodLockoutPolicy periodLockoutPolicy = (PeriodLockoutPolicy) webApplicationContext.getBean(DEFAULT_UAA_LOCKOUT_POLICY);
        LockoutPolicy lockoutPolicy = periodLockoutPolicy.getLockoutPolicy();
        assertThat(lockoutPolicy.getLockoutAfterFailures(), equalTo(10));
        assertThat(lockoutPolicy.getCountFailuresWithin(), equalTo(7200));
        assertThat(lockoutPolicy.getLockoutPeriodSeconds(), equalTo(600));
    }

    @Test
    public void testGlobalAuthenticationPolicyConfig() {
        environment.setProperty("authentication.policy.global.lockoutAfterFailures", "1");
        environment.setProperty("authentication.policy.global.countFailuresWithinSeconds", "2222");
        environment.setProperty("authentication.policy.global.lockoutPeriodSeconds", "152");
        webApplicationContext.refresh();
        PeriodLockoutPolicy globalPeriodLockoutPolicy = (PeriodLockoutPolicy) webApplicationContext.getBean(GLOBAL_LOCKOUT_POLICY);
        LockoutPolicy globalLockoutPolicy = globalPeriodLockoutPolicy.getLockoutPolicy();
        assertThat(globalLockoutPolicy.getLockoutAfterFailures(), equalTo(1));
        assertThat(globalLockoutPolicy.getCountFailuresWithin(), equalTo(2222));
        assertThat(globalLockoutPolicy.getLockoutPeriodSeconds(), equalTo(152));
    }
}
