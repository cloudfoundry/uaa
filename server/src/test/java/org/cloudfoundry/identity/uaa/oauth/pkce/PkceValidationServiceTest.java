package org.cloudfoundry.identity.uaa.oauth.pkce;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.PlainPkceVerifier;
import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.S256PkceVerifier;
import org.junit.Before;
import org.junit.Test;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

/**
 * 
 * @author Zoltan Maradics
 *
 */
public class PkceValidationServiceTest {

    private PkceValidationService pkceValidationService;
    private Map<String, String> authorizeRequestParameters;

    private final String longCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cME9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cME9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private final String shortCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c";
    private final String containsForbiddenCharactersCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM%";
    private final String validPlainCodeChallengeOrCodeVerifierParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private final String invalidCodeChallengeMethod = "InvalidMethod";

    @Before
    public void createPkceValidationService() throws Exception {
        pkceValidationService = new PkceValidationService(createPkceVerifiers());
        authorizeRequestParameters = new HashMap<>();
    }

    @Test
    public void testLongCodeChallengeParameter() throws Exception {
        assertFalse(PkceValidationService.matchWithPattern(longCodeChallengeOrCodeVerifierParameter));
    }

    @Test
    public void testShortCodeChallengeParameter() throws Exception {
        assertFalse(PkceValidationService.matchWithPattern(shortCodeChallengeOrCodeVerifierParameter));
    }

    @Test
    public void testContainsForbiddenCharactersCodeChallengeParameter() throws Exception {
        assertFalse(PkceValidationService
                .matchWithPattern(containsForbiddenCharactersCodeChallengeOrCodeVerifierParameter));
    }

    @Test
    public void testNullCodeChallengeOrCodeVerifierParameters() throws Exception {
        assertFalse(PkceValidationService.matchWithPattern(null));
    }

    @Test
    public void testValidCodeChallengeParameter() throws Exception {
        assertTrue(PkceValidationService.matchWithPattern(validPlainCodeChallengeOrCodeVerifierParameter));
    }

    @Test
    public void testInvalidCodeChallengeMethodParameter() throws Exception {
        assertFalse(pkceValidationService.isCodeChallengeMethodSupported(invalidCodeChallengeMethod));
    }

    @Test
    public void testNullCodeChallengeMethodParameter() throws Exception {
        assertFalse(pkceValidationService.isCodeChallengeMethodSupported(null));
    }

    @Test
    public void testS256CodeChallengeMethodParameter() throws Exception {
        assertTrue(pkceValidationService.isCodeChallengeMethodSupported("S256"));
    }

    @Test
    public void testPlainCodeChallengeMethodParameter() throws Exception {
        assertTrue(pkceValidationService.isCodeChallengeMethodSupported("plain"));
    }

    @Test
    public void testNoPkceParametersForEvaluation() throws Exception {
        assertTrue(pkceValidationService.checkAndValidate(authorizeRequestParameters, null, null));
    }

    @Test(expected = PkceValidationException.class)
    public void testCodeChallengeMissingForEvaluation() throws Exception {
        pkceValidationService.checkAndValidate(authorizeRequestParameters,
                validPlainCodeChallengeOrCodeVerifierParameter, null);
    }

    @Test(expected = PkceValidationException.class)
    public void testCodeVerifierMissingForEvaluation() throws Exception {
        authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
                validPlainCodeChallengeOrCodeVerifierParameter);
        pkceValidationService.checkAndValidate(authorizeRequestParameters, "", null);
    }

    @Test
    public void testNoCodeChallengeMethodForEvaluation() throws Exception {
        authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
                validPlainCodeChallengeOrCodeVerifierParameter);
        assertThat(pkceValidationService.checkAndValidate(authorizeRequestParameters,
                validPlainCodeChallengeOrCodeVerifierParameter, null), is(true));
    }

    @Test
    public void testPkceValidationServiceConstructorWithCodeChallengeMethodsMap() throws Exception {
        Set<String> testHashSet = new HashSet<>(Arrays.asList("S256", "plain"));
        assertEquals(testHashSet, pkceValidationService.getSupportedCodeChallengeMethods());
    }

    @Test
    public void testPlainCodeChallengeMethodForPublicUse() throws Exception {
        ClientDetails client = mock(ClientDetails.class);
        when(client.getAdditionalInformation()).thenReturn(Map.of(ClientConstants.ALLOW_PUBLIC, "true"));
        authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
                validPlainCodeChallengeOrCodeVerifierParameter);
        assertThrows(InvalidGrantException.class, () -> pkceValidationService.checkAndValidate(authorizeRequestParameters,
                validPlainCodeChallengeOrCodeVerifierParameter, client));
    }

    @Test
    public void testPlainCodeChallengeMethodForPublicUseNotAllowed() throws Exception {
        ClientDetails client = mock(ClientDetails.class);
        when(client.getAdditionalInformation()).thenReturn(Map.of("foo", "bar"));
        authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE,
                validPlainCodeChallengeOrCodeVerifierParameter);
        authorizeRequestParameters.put(PkceValidationService.CODE_CHALLENGE_METHOD, new PlainPkceVerifier().getCodeChallengeMethod());
        assertThat(pkceValidationService.checkAndValidate(authorizeRequestParameters,
                validPlainCodeChallengeOrCodeVerifierParameter, null), is(true));
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
