package org.cloudfoundry.identity.uaa.provider;

import java.util.Optional;

public abstract class BaseIdentityProviderValidator implements IdentityProviderConfigValidator {

  @Override
  public void validate(IdentityProvider<? extends AbstractIdentityProviderDefinition> provider) {
    AbstractIdentityProviderDefinition definition =
        Optional.ofNullable(provider)
            .orElseThrow(() -> new IllegalArgumentException("Provider cannot be null"))
            .getConfig();
    validate(definition);
  }

  public abstract void validate(AbstractIdentityProviderDefinition definition);
}
