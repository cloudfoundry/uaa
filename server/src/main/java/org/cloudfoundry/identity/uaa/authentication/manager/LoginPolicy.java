package org.cloudfoundry.identity.uaa.authentication.manager;

/**
 * This is a more generic version of AccountLoginPolicy interface, used for both User Login and
 * Client Authentication lockout mechanism.
 */
public interface LoginPolicy {

  Result isAllowed(String principalId);

  LockoutPolicyRetriever getLockoutPolicyRetriever();

  class Result {

    private final boolean isAllowed;
    private final int failureCount;

    public Result(boolean isAllowed, int failureCount) {
      this.isAllowed = isAllowed;
      this.failureCount = failureCount;
    }

    public boolean isAllowed() {
      return isAllowed;
    }

    public int getFailureCount() {
      return failureCount;
    }
  }
}
