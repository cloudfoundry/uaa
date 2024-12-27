package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

import org.junit.jupiter.api.Test;

import static org.cloudfoundry.identity.uaa.ratelimiting.core.http.CredentialIdTypeJWT.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

class CredentialIdTypeJWTTest extends CredentialIdTypeAbstractTestJWT<CredentialIdTypeJWT> {
    public static final String EMAIL_FROM_CLAIMS = "Claims+\"email\"\\s*:\\s*\"(.*?)\"";

    public CredentialIdTypeJWTTest() {
        super(EMAIL_FROM_CLAIMS, CredentialIdTypeJWT::new);
    }

    @Test
    void key() {
        assertEquals("JWT", credentialIdType.key());
    }

    @Test
    void factoryFlavors() {
        checkFlavor(null, AllJWT.class, JWT);
        checkFlavor("", AllJWT.class, JWT);
        checkFlavor(" ", AllJWT.class, JWT);
        checkFlavor(" 0 ", SectionJWT.class, b64section_HEADER);
        checkFlavor("header", SectionJWT.class, b64section_HEADER);
        checkFlavor("HEADERS", SectionJWT.class, b64section_HEADER);
        checkFlavor("1", SectionJWT.class, b64section_CLAIMS);
        checkFlavor("Payload", SectionJWT.class, b64section_CLAIMS);
        checkFlavor("claimS", SectionJWT.class, b64section_CLAIMS);
        checkFlavor("2", SectionJWT.class, b64section_SIGNATURE);
        checkFlavor("signaTure", SectionJWT.class, b64section_SIGNATURE);
        checkFlavor(EMAIL_FROM_CLAIMS, SectionRegexJWT.class, "|" + EMAIL_DEVIN + "|");

        AuthorizationCredentialIdExtractor factory = credentialIdType.factory("claims");
        when(requestInfo.getAuthorizationHeader()).thenReturn(null);
        assertNull(factory.mapAuthorizationToCredentialsID(requestInfo));
    }
}