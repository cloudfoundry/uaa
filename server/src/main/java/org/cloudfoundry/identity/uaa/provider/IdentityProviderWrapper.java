package org.cloudfoundry.identity.uaa.provider;

public class IdentityProviderWrapper<T extends AbstractIdentityProviderDefinition> {

  final IdentityProvider<T> provider;
  boolean override = true;

  public IdentityProviderWrapper(IdentityProvider<T> provider) {
    this.provider = provider;
  }

  public IdentityProvider<T> getProvider() {
    return provider;
  }

  public boolean isOverride() {
    return override;
  }

  public void setOverride(boolean override) {
    this.override = override;
  }
}
