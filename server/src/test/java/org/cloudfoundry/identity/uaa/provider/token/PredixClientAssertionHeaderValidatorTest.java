package org.cloudfoundry.identity.uaa.provider.token;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class PredixClientAssertionHeaderValidatorTest {
    
    private KeyPair pair;
    
    private String plainTextHeader = "tenantId=1234&deviceId=3";
    
    @Before
    public void createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        this.pair = keyGen.generateKeyPair();
    }
    
    @Test
    public void testValidationSuccess() throws Exception {
        byte[] headerSignature = getMockHeaderSignature(this.plainTextHeader);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(this.pair.getPublic());
        sig.update(this.plainTextHeader.getBytes());
        Assert.assertTrue(sig.verify(headerSignature));
    }
    
    @Test
    public void testValidationWrongPublicKey() throws Exception {
        //sign with private key generated in before method
        byte[] headerSignature = getMockHeaderSignature(this.plainTextHeader);
        Signature sig = Signature.getInstance("SHA256withRSA");
        /*create new key pair to verify with different public
        key then the key pair generated in the before method*/
        KeyPairGenerator differentPairKeyGen = KeyPairGenerator.getInstance("RSA");
        sig.initVerify(differentPairKeyGen.generateKeyPair().getPublic());
        sig.update(this.plainTextHeader.getBytes());
        //verify with public which does not match the private key
        Assert.assertFalse(sig.verify(headerSignature));
    }

    private byte[] getMockHeaderSignature(String plainTextHeader) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(this.pair.getPrivate());
        sig.update(plainTextHeader.getBytes("UTF-8"));
        return sig.sign();
    }
}
