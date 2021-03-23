package org.cloudfoundry.identity.uaa.account;

import java.util.Map;

public interface ChangeEmailService {

    void beginEmailChange(
            final String userId,
            final String userEmail,
            final String newEmail,
            final String clientId,
            final String redirectUri);

    Map<String, String> completeVerification(final String code);

}
