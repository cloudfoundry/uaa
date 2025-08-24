package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT.AllJWT;
import static org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT.SectionJWT;
import static org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT.SectionRegexJWT;
import static org.mockito.Mockito.when;

class CredentialIdTypeJWTTest extends CredentialIdTypeAbstractTestJWT<CredentialIdTypeJWT> {
    public static final String EMAIL_FROM_CLAIMS = "Claims+\"email\"\\s*:\\s*\"(.*?)\"";

    public CredentialIdTypeJWTTest() {
        super(EMAIL_FROM_CLAIMS, CredentialIdTypeJWT::new);
    }

    @Test
    void key() {
        assertThat(credentialIdType.key()).isEqualTo("JWT");
    }

    @Test
    void factoryFlavors() {
        checkFlavor(null, AllJWT.class, JWT);
        checkFlavor("", AllJWT.class, JWT);
        checkFlavor(" ", AllJWT.class, JWT);
        checkFlavor(" 0 ", SectionJWT.class, B64_SECTION_HEADER);
        checkFlavor("header", SectionJWT.class, B64_SECTION_HEADER);
        checkFlavor("HEADERS", SectionJWT.class, B64_SECTION_HEADER);
        checkFlavor("1", SectionJWT.class, B64_SECTION_CLAIMS);
        checkFlavor("Payload", SectionJWT.class, B64_SECTION_CLAIMS);
        checkFlavor("claimS", SectionJWT.class, B64_SECTION_CLAIMS);
        checkFlavor("2", SectionJWT.class, B64_SECTION_SIGNATURE);
        checkFlavor("signaTure", SectionJWT.class, B64_SECTION_SIGNATURE);
        checkFlavor(EMAIL_FROM_CLAIMS, SectionRegexJWT.class, "|" + EMAIL_DEVIN + "|");

        AuthorizationCredentialIdExtractor factory = credentialIdType.factory("claims");
        when(requestInfo.getAuthorizationHeader()).thenReturn(null);
        assertThat(factory.mapAuthorizationToCredentialsID(requestInfo)).isNull();
    }
}