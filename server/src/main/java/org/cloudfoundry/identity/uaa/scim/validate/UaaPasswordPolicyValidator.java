package org.cloudfoundry.identity.uaa.scim.validate;

import static org.cloudfoundry.identity.uaa.util.PasswordValidatorUtil.messageResolver;
import static org.cloudfoundry.identity.uaa.util.PasswordValidatorUtil.validator;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.LengthRule;
import org.passay.PasswordData;
import org.passay.PropertiesMessageResolver;
import org.passay.Rule;
import org.passay.RuleResult;
import org.springframework.beans.factory.annotation.Qualifier;

public class UaaPasswordPolicyValidator implements PasswordValidator {

  public static final String DEFAULT_MESSAGE_PATH = "/messages.properties";
  private static PropertiesMessageResolver messageResolver;

  static {
    messageResolver = messageResolver(DEFAULT_MESSAGE_PATH);
  }

  private final IdentityProviderProvisioning provisioning;
  private final PasswordPolicy globalDefaultPolicy;

  public UaaPasswordPolicyValidator(
      PasswordPolicy globalDefaultPolicy,
      final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning provisioning) {
    this.globalDefaultPolicy = globalDefaultPolicy;
    this.provisioning = provisioning;
  }

  @Override
  public void validate(String password) throws InvalidPasswordException {
    if (password == null) {
      password = "";
    }

    IdentityProvider<UaaIdentityProviderDefinition> idp =
        provisioning.retrieveByOriginIgnoreActiveFlag(
            OriginKeys.UAA, IdentityZoneHolder.get().getId());
    if (idp == null) {
      // should never happen
      return;
    }

    PasswordPolicy policy = globalDefaultPolicy;

    UaaIdentityProviderDefinition idpDefinition = idp.getConfig();
    if (idpDefinition != null && idpDefinition.getPasswordPolicy() != null) {
      policy = idpDefinition.getPasswordPolicy();
    }

    org.passay.PasswordValidator validator = validator(policy, messageResolver);
    RuleResult result = validator.validate(new PasswordData(password));
    if (!result.isValid()) {
      List<String> errorMessages = new LinkedList<>(validator.getMessages(result));
      if (!errorMessages.isEmpty()) {
        throw new InvalidPasswordException(errorMessages);
      }
    }
  }

  public org.passay.PasswordValidator getPasswordValidator(PasswordPolicy policy) {
    List<Rule> rules = new ArrayList<>();

    // length is always a rule. We do not allow blank password
    int minLength = Math.max(1, policy.getMinLength());
    int maxLength = policy.getMaxLength() > 0 ? policy.getMaxLength() : Integer.MAX_VALUE;
    rules.add(new LengthRule(minLength, maxLength));

    if (policy.getRequireUpperCaseCharacter() > 0) {
      rules.add(
          new CharacterRule(EnglishCharacterData.UpperCase, policy.getRequireUpperCaseCharacter()));
    }
    if (policy.getRequireLowerCaseCharacter() > 0) {
      rules.add(
          new CharacterRule(EnglishCharacterData.LowerCase, policy.getRequireLowerCaseCharacter()));
    }
    if (policy.getRequireDigit() > 0) {
      rules.add(new CharacterRule(EnglishCharacterData.Digit, policy.getRequireDigit()));
    }
    if (policy.getRequireSpecialCharacter() > 0) {
      rules.add(
          new CharacterRule(EnglishCharacterData.Special, policy.getRequireSpecialCharacter()));
    }
    return new org.passay.PasswordValidator(rules);
  }
}
