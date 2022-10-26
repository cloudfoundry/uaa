package org.cloudfoundry.identity.uaa.oauth.pkce.verifiers;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.PlainPkceVerifier;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author Zoltan Maradics
 *
 */
public class PlainPkceVerifierTest {
    
    private PlainPkceVerifier plainPkceVerifier;
    
    private final String matchParameter = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private final String mismatchParameter = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    
    @Before
    public void createPlainCodeChallengeMethod() throws Exception {
        plainPkceVerifier = new PlainPkceVerifier();
    }
    
    @Test
    public void testCodeVerifierMethodWithMatchParameters() throws Exception {
        assertTrue(plainPkceVerifier.verify(matchParameter, matchParameter));
    }
    
    @Test
    public void testCodeVerifierMethodWithMismatchParameters() throws Exception {
        assertFalse(plainPkceVerifier.verify(matchParameter, mismatchParameter));
    }
    
    @Test
    public void testCodeChallengeIsNull() throws Exception {
        assertFalse(plainPkceVerifier.verify(matchParameter, null));
    }
    
    @Test
    public void testCodeVerifierIsNull() throws Exception {
        assertFalse(plainPkceVerifier.verify(null, matchParameter));
    }

}
