package org.cloudfoundry.identity.uaa;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;

public class Configuration implements InitializingBean {
    private final Environment environment;
    private PeriodLockoutPolicy periodLockoutPolicy;

    public Configuration(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        int lockoutAfterFailures = Integer.parseInt(environment.getProperty("oauth.endpoint.lockoutAfterFailures", "5"));
        int lockoutPeriodSeconds = Integer.parseInt(environment.getProperty("oauth.endpoint.lockoutPeriodSeconds", "300"));
        int countFailuresWithin = Integer.parseInt(environment.getProperty("oauth.endpoint.countFailuresWithin", "3600"));
        periodLockoutPolicy = new PeriodLockoutPolicy(lockoutAfterFailures, lockoutPeriodSeconds, countFailuresWithin);
    }

    public PeriodLockoutPolicy getPeriodLockoutPolicy() {
        return periodLockoutPolicy;
    }

    public static class PeriodLockoutPolicy {

        private int lockoutAfterFailures;
        private int lockoutPeriodSeconds;
        private int countFailuresWithin;

        public PeriodLockoutPolicy(int lockoutAfterFailures, int lockoutPeriodSeconds, int countFailuresWithin) {
            this.lockoutAfterFailures = lockoutAfterFailures;
            this.lockoutPeriodSeconds = lockoutPeriodSeconds;
            this.countFailuresWithin = countFailuresWithin;
        }

        public int getLockoutAfterFailures() {
            return lockoutAfterFailures;
        }

        public int getLockoutPeriodSeconds() {
            return lockoutPeriodSeconds;
        }

        public int getCountFailuresWithin() {
            return countFailuresWithin;
        }
    }
}
