package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;

import java.util.List;

public interface SamlKeyManager {
    KeyWithCert getCredential(String keyName);

    KeyWithCert getDefaultCredential();

    String getDefaultCredentialName();

    List<KeyWithCert> getAvailableCredentials();

    List<String> getAvailableCredentialIds();
}
