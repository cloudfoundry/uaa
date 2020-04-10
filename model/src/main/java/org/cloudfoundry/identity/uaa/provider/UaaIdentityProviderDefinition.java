package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class UaaIdentityProviderDefinition extends AbstractIdentityProviderDefinition {

  private PasswordPolicy passwordPolicy;
  private LockoutPolicy lockoutPolicy;
  private boolean disableInternalUserManagement = false;

  public UaaIdentityProviderDefinition() {
  }

  public UaaIdentityProviderDefinition(PasswordPolicy passwordPolicy, LockoutPolicy lockoutPolicy) {
    this(passwordPolicy, lockoutPolicy, false);
  }

  public UaaIdentityProviderDefinition(
      PasswordPolicy passwordPolicy,
      LockoutPolicy lockoutPolicy,
      boolean disableInternalUserManagement) {
    this.passwordPolicy = passwordPolicy;
    this.lockoutPolicy = lockoutPolicy;
    this.disableInternalUserManagement = disableInternalUserManagement;
  }

  public PasswordPolicy getPasswordPolicy() {
    return passwordPolicy;
  }

  public void setPasswordPolicy(PasswordPolicy passwordPolicy) {
    this.passwordPolicy = passwordPolicy;
  }

  public LockoutPolicy getLockoutPolicy() {
    return lockoutPolicy;
  }

  public void setLockoutPolicy(LockoutPolicy lockoutPolicy) {
    this.lockoutPolicy = lockoutPolicy;
  }

  public boolean isDisableInternalUserManagement() {
    return disableInternalUserManagement;
  }

  public void setDisableInternalUserManagement(boolean disableInternalUserManagement) {
    this.disableInternalUserManagement = disableInternalUserManagement;
  }
}
