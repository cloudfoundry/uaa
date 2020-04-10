package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.manager.LoginPolicy.Result;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Locks an account out for a configured period based on the number of failed logins since a
 * specific time in the past.
 *
 * <p>Queries the audit service to obtain the relevant data for the user.
 *
 * @author Luke Taylor
 */
public class PeriodLockoutPolicy implements AccountLoginPolicy {

  private final Logger logger = LoggerFactory.getLogger(getClass());

  private final LoginPolicy loginPolicy;
  private final LoginPolicy mfaPolicy;

  public PeriodLockoutPolicy(LoginPolicy loginPolicy, LoginPolicy mfaPolicy) {
    this.loginPolicy = loginPolicy;
    this.mfaPolicy = mfaPolicy;
  }

  public LockoutPolicy getDefaultLockoutPolicy() {
    return this.loginPolicy.getLockoutPolicyRetriever().getDefaultLockoutPolicy();
  }

  @Override
  public boolean isAllowed(UaaUser user, Authentication a) throws AuthenticationException {
    Result loginResult = loginPolicy.isAllowed(user.getId());
    Result mfaResult = mfaPolicy.isAllowed(user.getId());
    if (loginResult.isAllowed() && mfaResult.isAllowed()) {
      return true;
    }
    logger.warn(
        "User "
            + user.getUsername()
            + " and id "
            + user.getId()
            + " has "
            + loginResult.getFailureCount()
            + " failed user logins within the last checking period."
            + " and "
            + mfaResult.getFailureCount()
            + " failed  mfa attempts within the last checking period.");
    return false;
  }
}
