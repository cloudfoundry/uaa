package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.cloudfoundry.identity.uaa.authentication.GenericPasswordPolicy;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientSecretPolicy extends GenericPasswordPolicy<ClientSecretPolicy> {

  public static final String CLIENT_SECRET_POLICY_FIELD = "clientSecretPolicy";
  @JsonIgnore
  private int expireSecretInMonths;

  public ClientSecretPolicy() {
    super();
    this.expireSecretInMonths = -1;
  }

  public ClientSecretPolicy(
      int minLength,
      int maxLength,
      int requireUpperCaseCharacter,
      int requireLowerCaseCharacter,
      int requireDigit,
      int requireSpecialCharacter,
      int expireSecretInMonths) {
    super(
        minLength,
        maxLength,
        requireUpperCaseCharacter,
        requireLowerCaseCharacter,
        requireDigit,
        requireSpecialCharacter);
    this.setExpireSecretInMonths(expireSecretInMonths);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + expireSecretInMonths;
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

    ClientSecretPolicy that = (ClientSecretPolicy) obj;
    return super.equals(obj) && this.expireSecretInMonths == that.expireSecretInMonths;
  }

  public int getExpireSecretInMonths() {
    return expireSecretInMonths;
  }

  public ClientSecretPolicy setExpireSecretInMonths(int expireSecretInMonths) {
    this.expireSecretInMonths = expireSecretInMonths;
    return this;
  }

  @Override
  public boolean allPresentAndPositive() {
    return super.allPresentAndPositive() && expireSecretInMonths >= 0;
  }
}
