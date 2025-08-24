package org.cloudfoundry.identity.uaa.oauth.pkce.verifiers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Zoltan Maradics
 */
class S256PkceVerifierTest {

    private S256PkceVerifier s256CodeChallengeMethod;

    private static final String VALID_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String VALID_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @BeforeEach
    void createS256CodeChallengeMethod() {
        s256CodeChallengeMethod = new S256PkceVerifier();
    }

    @Test
    void codeVerifierMethodWithMatchParameters() {
        assertThat(s256CodeChallengeMethod.verify(VALID_CODE_VERIFIER, VALID_CODE_CHALLENGE)).isTrue();
    }

    @Test
    void codeVerifierMethodWithMismatchParameters() {
        assertThat(s256CodeChallengeMethod.verify(VALID_CODE_VERIFIER, VALID_CODE_VERIFIER)).isFalse();
    }

    @Test
    void codeChallengeIsNull() {
        assertThat(s256CodeChallengeMethod.verify(VALID_CODE_VERIFIER, null)).isFalse();
    }

    @Test
    void codeVerifierIsNull() {
        assertThat(s256CodeChallengeMethod.verify(null, VALID_CODE_CHALLENGE)).isFalse();
    }
}
