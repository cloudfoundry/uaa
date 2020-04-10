package org.cloudfoundry.identity.uaa.provider;

public class LockoutPolicy {

  private int lockoutPeriodSeconds;
  private int lockoutAfterFailures;
  private int countFailuresWithin;

  public LockoutPolicy() {
    lockoutPeriodSeconds = lockoutAfterFailures = countFailuresWithin = -1;
  }

  public LockoutPolicy(
      int countFailuresWithin, int lockoutAfterFailures, int lockoutPeriodSeconds) {
    this.countFailuresWithin = countFailuresWithin;
    this.lockoutAfterFailures = lockoutAfterFailures;
    this.lockoutPeriodSeconds = lockoutPeriodSeconds;
  }

  public int getLockoutPeriodSeconds() {
    return lockoutPeriodSeconds;
  }

  public LockoutPolicy setLockoutPeriodSeconds(int lockoutPeriod) {
    this.lockoutPeriodSeconds = lockoutPeriod;
    return this;
  }

  public int getLockoutAfterFailures() {
    return lockoutAfterFailures;
  }

  public LockoutPolicy setLockoutAfterFailures(int allowedFailures) {
    this.lockoutAfterFailures = allowedFailures;
    return this;
  }

  public int getCountFailuresWithin() {
    return countFailuresWithin;
  }

  /**
   * Only audit events within the preceding interval will be considered.
   *
   * @param interval the history period to consider (in seconds)
   */
  public LockoutPolicy setCountFailuresWithin(int interval) {
    this.countFailuresWithin = interval;
    return this;
  }

  public boolean allPresentAndPositive() {
    return lockoutPeriodSeconds >= 0 && lockoutAfterFailures >= 0 && countFailuresWithin >= 0;
  }
}
