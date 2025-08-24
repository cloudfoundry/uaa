package org.cloudfoundry.identity.uaa.oauth.pkce.verifiers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Zoltan Maradics
 */
class PlainPkceVerifierTest {

    private PlainPkceVerifier plainPkceVerifier;

    private static final String MATCH_PARAMETER = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final String MISMATCH_PARAMETER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @BeforeEach
    void createPlainCodeChallengeMethod() {
        plainPkceVerifier = new PlainPkceVerifier();
    }

    @Test
    void codeVerifierMethodWithMatchParameters() {
        assertThat(plainPkceVerifier.verify(MATCH_PARAMETER, MATCH_PARAMETER)).isTrue();
    }

    @Test
    void codeVerifierMethodWithMismatchParameters() {
        assertThat(plainPkceVerifier.verify(MATCH_PARAMETER, MISMATCH_PARAMETER)).isFalse();
    }

    @Test
    void codeChallengeIsNull() {
        assertThat(plainPkceVerifier.verify(MATCH_PARAMETER, null)).isFalse();
    }

    @Test
    void codeVerifierIsNull() {
        assertThat(plainPkceVerifier.verify(null, MATCH_PARAMETER)).isFalse();
    }
}
