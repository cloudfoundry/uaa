package org.cloudfoundry.identity.uaa.authentication;

public abstract class GenericPasswordPolicy<T extends GenericPasswordPolicy<T>> {

  private int minLength;
  private int maxLength;
  private int requireUpperCaseCharacter;
  private int requireLowerCaseCharacter;
  private int requireDigit;
  private int requireSpecialCharacter;

  public GenericPasswordPolicy() {
    minLength =
        maxLength =
            requireUpperCaseCharacter =
                requireLowerCaseCharacter = requireDigit = requireSpecialCharacter = -1;
  }

  public GenericPasswordPolicy(
      int minLength,
      int maxLength,
      int requireUpperCaseCharacter,
      int requireLowerCaseCharacter,
      int requireDigit,
      int requireSpecialCharacter) {
    this.minLength = minLength;
    this.maxLength = maxLength;
    this.requireUpperCaseCharacter = requireUpperCaseCharacter;
    this.requireLowerCaseCharacter = requireLowerCaseCharacter;
    this.requireDigit = requireDigit;
    this.requireSpecialCharacter = requireSpecialCharacter;
  }

  public int getMinLength() {
    return minLength;
  }

  public T setMinLength(int minLength) {
    this.minLength = minLength;
    return (T) this;
  }

  public int getMaxLength() {
    return maxLength;
  }

  public T setMaxLength(int maxLength) {
    this.maxLength = maxLength;
    return (T) this;
  }

  public int getRequireUpperCaseCharacter() {
    return requireUpperCaseCharacter;
  }

  public T setRequireUpperCaseCharacter(int requireUpperCaseCharacter) {
    this.requireUpperCaseCharacter = requireUpperCaseCharacter;
    return (T) this;
  }

  public int getRequireLowerCaseCharacter() {
    return requireLowerCaseCharacter;
  }

  public T setRequireLowerCaseCharacter(int requireLowerCaseCharacter) {
    this.requireLowerCaseCharacter = requireLowerCaseCharacter;
    return (T) this;
  }

  public int getRequireDigit() {
    return requireDigit;
  }

  public T setRequireDigit(int requireDigit) {
    this.requireDigit = requireDigit;
    return (T) this;
  }

  public int getRequireSpecialCharacter() {
    return requireSpecialCharacter;
  }

  public T setRequireSpecialCharacter(int requireSpecialCharacter) {
    this.requireSpecialCharacter = requireSpecialCharacter;
    return (T) this;
  }

  public boolean allPresentAndPositive() {
    return minLength >= 0
        && maxLength >= 0
        && requireUpperCaseCharacter >= 0
        && requireLowerCaseCharacter >= 0
        && requireDigit >= 0
        && requireSpecialCharacter >= 0;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    GenericPasswordPolicy<?> that = (GenericPasswordPolicy<?>) o;

    if (minLength != that.minLength) {
      return false;
    }
    if (maxLength != that.maxLength) {
      return false;
    }
    if (requireUpperCaseCharacter != that.requireUpperCaseCharacter) {
      return false;
    }
    if (requireLowerCaseCharacter != that.requireLowerCaseCharacter) {
      return false;
    }
    if (requireDigit != that.requireDigit) {
      return false;
    }
    if (requireSpecialCharacter != that.requireSpecialCharacter) {
      return false;
    }
    return true;
  }

  @Override
  public int hashCode() {
    int result = minLength;
    result = 31 * result + maxLength;
    result = 31 * result + requireUpperCaseCharacter;
    result = 31 * result + requireLowerCaseCharacter;
    result = 31 * result + requireDigit;
    result = 31 * result + requireSpecialCharacter;
    return result;
  }
}
