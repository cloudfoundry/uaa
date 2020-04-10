package org.cloudfoundry.identity.uaa.provider.saml;

import java.security.cert.X509Certificate;
import java.util.Set;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.stereotype.Component;

@Component("zoneAwareSamlSpKeyManager")
@DependsOn("identityZoneHolderInitializer")
public class ZoneAwareKeyManager implements KeyManager {

  @Override
  public Credential getCredential(String keyName) {
    return IdentityZoneHolder.getSamlSPKeyManager().getCredential(keyName);
  }

  @Override
  public Credential getDefaultCredential() {
    return IdentityZoneHolder.getSamlSPKeyManager().getDefaultCredential();
  }

  @Override
  public String getDefaultCredentialName() {
    return IdentityZoneHolder.getSamlSPKeyManager().getDefaultCredentialName();
  }

  @Override
  public Set<String> getAvailableCredentials() {
    return IdentityZoneHolder.getSamlSPKeyManager().getAvailableCredentials();
  }

  @Override
  public X509Certificate getCertificate(String alias) {
    return IdentityZoneHolder.getSamlSPKeyManager().getCertificate(alias);
  }

  @Override
  public Iterable<Credential> resolve(CriteriaSet criteria) throws SecurityException {
    return IdentityZoneHolder.getSamlSPKeyManager().resolve(criteria);
  }

  @Override
  public Credential resolveSingle(CriteriaSet criteria) throws SecurityException {
    return IdentityZoneHolder.getSamlSPKeyManager().resolveSingle(criteria);
  }
}
