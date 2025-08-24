package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWTjsonField.SectionFieldJWT;
import static org.mockito.Mockito.when;

class CredentialIdTypeJWTjsonFieldTest extends CredentialIdTypeAbstractTestJWT<CredentialIdTypeJWTjsonField> {
    public static final String EMAIL_FROM_CLAIMS = "claims:email";

    public CredentialIdTypeJWTjsonFieldTest() {
        super(EMAIL_FROM_CLAIMS, CredentialIdTypeJWTjsonField::new);
    }

    @Test
    void key() {
        assertThat(credentialIdType.key()).isEqualTo("JWTjsonField");
    }

    @Test
    void factoryFlavors() {
        checkFlavor(EMAIL_FROM_CLAIMS, SectionFieldJWT.class, "|" + EMAIL_DEVIN + "|");

        AuthorizationCredentialIdExtractor factory = credentialIdType.factory(EMAIL_FROM_CLAIMS);
        when(requestInfo.getAuthorizationHeader()).thenReturn(null);
        assertThat(factory.mapAuthorizationToCredentialsID(requestInfo)).isNull();
    }
}