package org.cloudfoundry.identity.uaa.provider.saml;

import javax.servlet.http.HttpServletRequest;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.saml.storage.HttpSessionStorage;
import org.springframework.security.saml.storage.SAMLMessageStorage;
import org.springframework.security.saml.storage.SAMLMessageStorageFactory;

public class SamlSessionStorageFactory implements SAMLMessageStorageFactory {

  @Override
  public synchronized SAMLMessageStorage getMessageStorage(HttpServletRequest request) {
    if (IdentityZoneHolder.get().getConfig().getSamlConfig().isDisableInResponseToCheck()) {
      // add the ability to disable inResponseTo check
      // https://docs.spring.io/spring-security-saml/docs/current/reference/html/chapter-troubleshooting.html
      return null;
    }
    return new HttpSessionStorage(request);
  }
}
