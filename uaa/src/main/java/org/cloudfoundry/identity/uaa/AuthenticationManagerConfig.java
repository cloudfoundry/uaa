package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.manager.AuthzAuthenticationManager;
import org.cloudfoundry.identity.uaa.authentication.manager.PeriodLockoutPolicy;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

@org.springframework.context.annotation.Configuration
public class AuthenticationManagerConfig {

    @Bean
    public Configuration configuration(Environment environment) {
        return new Configuration(environment);
    }

    @Bean
    public AuthzAuthenticationManager uaaAuthenticationMgr(UaaUserDatabase uaaUserDatabase, PeriodLockoutPolicy periodLockoutPolicy) {
        return getAuthzAuthenticationManager(uaaUserDatabase, periodLockoutPolicy);
    }

    @Bean
    public AuthzAuthenticationManager authzAuthenticationMgr(UaaUserDatabase uaaUserDatabase, PeriodLockoutPolicy periodLockoutPolicy) {
        return getAuthzAuthenticationManager(uaaUserDatabase, periodLockoutPolicy);
    }

    @Bean
    public PeriodLockoutPolicy periodLockoutPolicy(Configuration configuration, @Qualifier("jdbcAuditService") UaaAuditService uaaAuditService) {
        PeriodLockoutPolicy periodLockoutPolicy = new PeriodLockoutPolicy(uaaAuditService);
        periodLockoutPolicy.setLockoutAfterFailures(configuration.getPeriodLockoutPolicy().getLockoutAfterFailures());
        periodLockoutPolicy.setLockoutPeriodSeconds(configuration.getPeriodLockoutPolicy().getLockoutPeriodSeconds());
        return periodLockoutPolicy;
    }

    private AuthzAuthenticationManager getAuthzAuthenticationManager(UaaUserDatabase uaaUserDatabase, PeriodLockoutPolicy periodLockoutPolicy) {
        AuthzAuthenticationManager uaaAuthenticationMgr = new AuthzAuthenticationManager(uaaUserDatabase);
        uaaAuthenticationMgr.setAccountLoginPolicy(periodLockoutPolicy);
        uaaAuthenticationMgr.setOrigin("uaa");
        return uaaAuthenticationMgr;
    }
}
