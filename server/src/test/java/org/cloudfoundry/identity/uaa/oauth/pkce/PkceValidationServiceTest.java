package org.cloudfoundry.identity.uaa.oauth.pkce;

import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.PlainPkceVerifier;
import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.S256PkceVerifier;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Zoltan Maradics
 */
class PkceValidationServiceTest {

    private PkceValidationService pkceValidationService;
    private Map<String, String> authorizeRequestParameters;

    private final String longCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cME9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cME9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private final String shortCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c";
    private final String containsForbiddenCharactersCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM%";
    private final String validPlainCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private final String invalidCodeChallengeMethod = "InvalidMethod";

    @BeforeEach
    void createPkceValidationService() {
        pkceValidationService = new PkceValidationService(createPkceVerifiers());
        authorizeRequestParameters = new HashMap<>();
    }

    @Test
    void longCodeChallengeParameter() {
        assertThat(PkceValidationService.matchWithPattern(longCodeChallengeOrCodeVerifierParameter)).isFalse();
    }

    @Test
    void shortCodeChallengeParameter() {
        assertThat(PkceValidationService.matchWithPattern(shortCodeChallengeOrCodeVerifierParameter)).isFalse();
    }

    @Test
    void containsForbiddenCharactersCodeChallengeParameter() {
        assertThat(PkceValidationService
                .matchWithPattern(containsForbiddenCharactersCodeChallengeOrCodeVerifierParameter)).isFalse();
    }

    @Test
    void nullCodeChallengeOrCodeVerifierParameters() {
        assertThat(PkceValidationService.matchWithPattern(null)).isFalse();
    }

    @Test
    void validCodeChallengeParameter() {
        assertThat(PkceValidationService.matchWithPattern(validPlainCodeChallengeOrCodeVerifierParameter)).isTrue();
    }

    @Test
    void invalidCodeChallengeMethodParameter() {
        assertThat(pkceValidationService.isCodeChallengeMethodSupported(invalidCodeChallengeMethod)).isFalse();
    }

    @Test
    void nullCodeChallengeMethodParameter() {
        assertThat(pkceValidationService.isCodeChallengeMethodSupported(null)).isFalse();
    }

    @Test
    void s256CodeChallengeMethodParameter() {
        assertThat(pkceValidationService.isCodeChallengeMethodSupported("S256")).isTrue();
    }

    @Test
    void plainCodeChallengeMethodParameter() {
        assertThat(pkceValidationService.isCodeChallengeMethodSupported("plain")).isTrue();
    }

    @Test
    void noPkceParametersForEvaluation() throws Exception {
        assertThat(pkceValidationService.checkAndValidate(authorizeRequestParameters, null, null)).isTrue();
    }

    @Test
    void codeChallengeMissingForEvaluation() {
        assertThatExceptionOfType(PkceValidationException.class).isThrownBy(() ->
                pkceValidationService.checkAndValidate(authorizeRequestParameters,
                        validPlainCodeChallengeOrCodeVerifierParameter, null));
    }

    @Test
    void codeVerifierMissingForEvaluation() {
        authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
                validPlainCodeChallengeOrCodeVerifierParameter);
        assertThatExceptionOfType(PkceValidationException.class).isThrownBy(() ->
                pkceValidationService.checkAndValidate(authorizeRequestParameters, "", null));
    }

    @Test
    void noCodeChallengeMethodForEvaluation() throws Exception {
        authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
                validPlainCodeChallengeOrCodeVerifierParameter);
        assertThat(pkceValidationService.checkAndValidate(authorizeRequestParameters,
                validPlainCodeChallengeOrCodeVerifierParameter, null)).isTrue();
    }

    @Test
    void pkceValidationServiceConstructorWithCodeChallengeMethodsMap() {
        Set<String> testHashSet = new HashSet<>(Arrays.asList("S256", "plain"));
        assertThat(pkceValidationService.getSupportedCodeChallengeMethods()).isEqualTo(testHashSet);
    }

    @Test
    void plainCodeChallengeMethodForPublicUse() {
        ClientDetails client = mock(ClientDetails.class);
        when(client.getAdditionalInformation()).thenReturn(Map.of(ClientConstants.ALLOW_PUBLIC, "true"));
        authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
                validPlainCodeChallengeOrCodeVerifierParameter);
        assertThatExceptionOfType(InvalidGrantException.class).isThrownBy(() -> pkceValidationService.checkAndValidate(authorizeRequestParameters,
                validPlainCodeChallengeOrCodeVerifierParameter, client));
    }

    @Test
    void plainCodeChallengeMethodForPublicUseNotAllowed() throws Exception {
        ClientDetails client = mock(ClientDetails.class);
        when(client.getAdditionalInformation()).thenReturn(Map.of("foo", "bar"));
        authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
                validPlainCodeChallengeOrCodeVerifierParameter);
        authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE_METHOD, new PlainPkceVerifier().getCodeChallengeMethod());
        assertThat(pkceValidationService.checkAndValidate(authorizeRequestParameters,
                validPlainCodeChallengeOrCodeVerifierParameter, null)).isTrue();
    }

    private Map<String, PkceVerifier> createPkceVerifiers() {
        S256PkceVerifier s256PkceVerifier = new S256PkceVerifier();
        PlainPkceVerifier plainPkceVerifier = new PlainPkceVerifier();
        Map<String, PkceVerifier> pkceVerifiers = new HashMap<>();
        pkceVerifiers.put(plainPkceVerifier.getCodeChallengeMethod(), plainPkceVerifier);
        pkceVerifiers.put(s256PkceVerifier.getCodeChallengeMethod(), s256PkceVerifier);
        return pkceVerifiers;
    }
}
