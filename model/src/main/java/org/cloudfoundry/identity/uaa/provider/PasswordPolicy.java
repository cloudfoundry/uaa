package org.cloudfoundry.identity.uaa.provider;

import java.util.Date;
import org.cloudfoundry.identity.uaa.authentication.GenericPasswordPolicy;

public class PasswordPolicy extends GenericPasswordPolicy<PasswordPolicy> {

  public static final String PASSWORD_POLICY_FIELD = "passwordPolicy";
  private Date passwordNewerThan;
  private int expirePasswordInMonths;

  public PasswordPolicy() {
    super();
    this.expirePasswordInMonths = -1;
  }

  public PasswordPolicy(
      int minLength,
      int maxLength,
      int requireUpperCaseCharacter,
      int requireLowerCaseCharacter,
      int requireDigit,
      int requireSpecialCharacter,
      int expirePasswordInMonths) {

    super(
        minLength,
        maxLength,
        requireUpperCaseCharacter,
        requireLowerCaseCharacter,
        requireDigit,
        requireSpecialCharacter);
    this.setExpirePasswordInMonths(expirePasswordInMonths);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + expirePasswordInMonths;
    result = prime * result + ((passwordNewerThan == null) ? 0 : passwordNewerThan.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false;
    }

    PasswordPolicy that = (PasswordPolicy) obj;
    return super.equals(obj) && this.expirePasswordInMonths == that.expirePasswordInMonths;
  }

  public Date getPasswordNewerThan() {
    return passwordNewerThan;
  }

  public void setPasswordNewerThan(Date passwordNewerThan) {
    this.passwordNewerThan = passwordNewerThan;
  }

  public int getExpirePasswordInMonths() {
    return expirePasswordInMonths;
  }

  public PasswordPolicy setExpirePasswordInMonths(int expirePasswordInMonths) {
    this.expirePasswordInMonths = expirePasswordInMonths;
    return this;
  }

  @Override
  public boolean allPresentAndPositive() {
    return super.allPresentAndPositive() && expirePasswordInMonths >= 0;
  }
}
