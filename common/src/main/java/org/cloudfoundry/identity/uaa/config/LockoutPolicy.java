package org.cloudfoundry.identity.uaa.config;

public class LockoutPolicy {
    private int lockoutPeriodSeconds;
    private int lockoutAfterFailures;
    private int countFailuresWithin;

    public LockoutPolicy() {
        lockoutPeriodSeconds = lockoutAfterFailures = countFailuresWithin = -1;
    }

    public void setLockoutPeriodSeconds(int lockoutPeriod) {
        this.lockoutPeriodSeconds = lockoutPeriod;
    }

    public void setLockoutAfterFailures(int allowedFailures) {
        this.lockoutAfterFailures = allowedFailures;
    }

    /**
     * Only audit events within the preceding interval will be considered
     *
     * @param interval the history period to consider (in seconds)
     */
    public void setCountFailuresWithin(int interval) {
        this.countFailuresWithin = interval;
    }

    public int getLockoutPeriodSeconds() {
        return lockoutPeriodSeconds;
    }

    public int getLockoutAfterFailures() {
        return lockoutAfterFailures;
    }

    public int getCountFailuresWithin() {
        return countFailuresWithin;
    }

    public boolean allPresentAndPositive() {
        return lockoutPeriodSeconds >= 0 && lockoutAfterFailures >= 0 && countFailuresWithin >= 0;
    }
}
