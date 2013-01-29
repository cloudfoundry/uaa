package org.cloudfoundry.identity.uaa.oauth.token;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;


public class SignerProviderTests {

	@Test
	public void testSignedProviderSymmetricKeys() {
		SignerProvider signerProvider = new SignerProvider();
		signerProvider.setSigningKey("testkey");
		signerProvider.setVerifierKey("testkey");

		assertNotNull(signerProvider.getSigner());
		assertNotNull(signerProvider.getVerifier());

		byte[] signedValue = signerProvider.getSigner().sign("joel".getBytes());
		signerProvider.getVerifier().verify("joel".getBytes(), signedValue);
	}

	@Test
	public void testSignedProviderAsymmetricKeys() {
		SignerProvider signerProvider = new SignerProvider();
		signerProvider.setSigningKey("-----BEGIN RSA PRIVATE KEY-----\n" +
							        "MIICXgIBAAKBgQDAcxw6ilnDn4FPkl21wA0H3vNyJLtsbwUTvB8Ka61wCVpnoNdI\n" +
							        "HQOjuCptz32VSCcjYj4djWlMBPTq0Z9svcWi3hnegk/57FFqE3crdTfu9lPZlHyx\n" +
							        "k3r2aKvnm/dWfpqFXyYsrK8y00bNC8UFY5D/bsl/AvekXizi/hpTLGrp9QIDAQAB\n" +
							        "AoGABN2kNBK1bE3HHjTsK6E8cxt++j7VgktYTIRwIHpSe0exQnd9mfQp2GTapcYe\n" +
							        "Pb0CSFG+kk61/9cMPjeomT4/FfDFnQd4AqNYOJUlh0r+AOeSZTLf3ZAYC1osi4o6\n" +
							        "UH4zrNZenO5ZfxRvxIxR8oDBwjMlbtCDLQwp1BIWhjoGce0CQQD+VGHqef9+hET8\n" +
							        "MNmFEKz6Qrf0gQX75o+CNsar9qPyeL1/whuhd1wxuXPNeeGViwRXOpmQDL93JySW\n" +
							        "pzLDHOHDAkEAwbavkGn4Dn/A67CLo6HKAbyoTcgAQyGK3TQhSBaGSCCxdro6m+o3\n" +
							        "DAYDLOnVrOu5Iwwy3CF/zz/MUliovxnR5wJBAK/oi2UThqzqLZDE9N59fzcFiJi7\n" +
							        "2Pi3KtFks5tjV1gxPNit2FCg7wqRe9BGGcpGQfVXWblxp8hxMXRmJs0fH+MCQQCw\n" +
							        "wZmBFLCbykamyPkh3kcNPq/0CULz/m9PWHnl5Wex+OL1iwhfrF9+QR40pUmr94t/\n" +
							        "R2pBIvAUlApEOVIAzfaRAkEA6mq3t/N5DNIfhYD87+mtwMy5KvWut799bCMpzoWP\n" +
							        "q5vpbVbOxo/LoUPzeSThspSF/NlVlx6T+HCq+nVcPV3VfA==\n" +
							        "-----END RSA PRIVATE KEY-----");
		signerProvider.setVerifierKey("-----BEGIN RSA PRIVATE KEY-----\n" +
							        "MIICXgIBAAKBgQDAcxw6ilnDn4FPkl21wA0H3vNyJLtsbwUTvB8Ka61wCVpnoNdI\n" +
							        "HQOjuCptz32VSCcjYj4djWlMBPTq0Z9svcWi3hnegk/57FFqE3crdTfu9lPZlHyx\n" +
							        "k3r2aKvnm/dWfpqFXyYsrK8y00bNC8UFY5D/bsl/AvekXizi/hpTLGrp9QIDAQAB\n" +
							        "AoGABN2kNBK1bE3HHjTsK6E8cxt++j7VgktYTIRwIHpSe0exQnd9mfQp2GTapcYe\n" +
							        "Pb0CSFG+kk61/9cMPjeomT4/FfDFnQd4AqNYOJUlh0r+AOeSZTLf3ZAYC1osi4o6\n" +
							        "UH4zrNZenO5ZfxRvxIxR8oDBwjMlbtCDLQwp1BIWhjoGce0CQQD+VGHqef9+hET8\n" +
							        "MNmFEKz6Qrf0gQX75o+CNsar9qPyeL1/whuhd1wxuXPNeeGViwRXOpmQDL93JySW\n" +
							        "pzLDHOHDAkEAwbavkGn4Dn/A67CLo6HKAbyoTcgAQyGK3TQhSBaGSCCxdro6m+o3\n" +
							        "DAYDLOnVrOu5Iwwy3CF/zz/MUliovxnR5wJBAK/oi2UThqzqLZDE9N59fzcFiJi7\n" +
							        "2Pi3KtFks5tjV1gxPNit2FCg7wqRe9BGGcpGQfVXWblxp8hxMXRmJs0fH+MCQQCw\n" +
							        "wZmBFLCbykamyPkh3kcNPq/0CULz/m9PWHnl5Wex+OL1iwhfrF9+QR40pUmr94t/\n" +
							        "R2pBIvAUlApEOVIAzfaRAkEA6mq3t/N5DNIfhYD87+mtwMy5KvWut799bCMpzoWP\n" +
							        "q5vpbVbOxo/LoUPzeSThspSF/NlVlx6T+HCq+nVcPV3VfA==\n" +
							        "-----END RSA PRIVATE KEY-----");

		assertNotNull(signerProvider.getSigner());
		assertNotNull(signerProvider.getVerifier());

		byte[] signedValue = signerProvider.getSigner().sign("joel".getBytes());
		signerProvider.getVerifier().verify("joel".getBytes(), signedValue);
	}
}
