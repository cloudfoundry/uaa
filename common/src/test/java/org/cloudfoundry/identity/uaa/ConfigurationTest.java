package org.cloudfoundry.identity.uaa;

import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;

public class ConfigurationTest {
    @Test
    public void testPeriodLockoutPolicyDefaults() throws Exception {
        Configuration configuration = new Configuration(new MockEnvironment());
        configuration.afterPropertiesSet();
        Assert.assertThat(configuration.getPeriodLockoutPolicy().getLockoutAfterFailures(), Matchers.equalTo(5));
        Assert.assertThat(configuration.getPeriodLockoutPolicy().getLockoutPeriodSeconds(), Matchers.equalTo(300));
        Assert.assertThat(configuration.getPeriodLockoutPolicy().getCountFailuresWithin(), Matchers.equalTo(3600));
    }

    @Test
    public void testPeriodLockoutPolicy() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        environment.setProperty("oauth.endpoint.lockoutAfterFailures", "10");
        environment.setProperty("oauth.endpoint.lockoutPeriodSeconds", "600");
        environment.setProperty("oauth.endpoint.countFailuresWithin", "7200");
        Configuration configuration = new Configuration(environment);
        configuration.afterPropertiesSet();
        Assert.assertThat(configuration.getPeriodLockoutPolicy().getLockoutAfterFailures(), Matchers.equalTo(10));
        Assert.assertThat(configuration.getPeriodLockoutPolicy().getLockoutPeriodSeconds(), Matchers.equalTo(600));
        Assert.assertThat(configuration.getPeriodLockoutPolicy().getCountFailuresWithin(), Matchers.equalTo(7200));
    }
}