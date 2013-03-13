/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.oauth.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.Assert;

/**
 * A class that knows how to provide the signing and verification keys
 *
 * @author Joel D'sa
 * @author Luke Taylor
 *
 */
public class SignerProvider implements InitializingBean {

	private final Log logger = LogFactory.getLog(getClass());
	private String verifierKey = new RandomValueStringGenerator().generate();
	private String signingKey = verifierKey;
	private Signer signer = new MacSigner(verifierKey);

	@Override
	public void afterPropertiesSet() throws Exception {
		if (signer instanceof RsaSigner) {
			RsaVerifier verifier;
			try {
				verifier = new RsaVerifier(verifierKey);
			}
			catch (Exception e) {
				throw new RuntimeException("Unable to create an RSA verifier from verifierKey", e);
			}

			byte[] test = "test".getBytes();
			try {
				verifier.verify(test, signer.sign(test));
				logger.info("Signing and verification RSA keys match");
			}
			catch (InvalidSignatureException e) {
				throw new RuntimeException("Signing and verification RSA keys do not match", e);
			}
		}
		else {
			Assert.state(this.signingKey == this.verifierKey,
					"For MAC signing you do not need to specify the verifier key separately, and if you do it must match the signing key");
		}
	}

	public Signer getSigner() {
		return signer;
	}
	
	/**
	 * @return the verifierKey
	 */
	public String getVerifierKey() {
		return verifierKey;
	}

	/**
	 * @return true if the signer represents a public (asymmetric) key pair
	 */
	public boolean isPublic() {
		return verifierKey.startsWith("-----BEGIN");
	}

	public SignatureVerifier getVerifier() {
		if (isAssymetricKey(signingKey)) {
			return new RsaVerifier(verifierKey);
		}
		else {
			return new MacSigner(verifierKey);
		}
	}

	/**
	 * Sets the JWT signing key. It can be either a simple MAC key or an RSA key. RSA keys should be in OpenSSH format,
	 * as produced by <tt>ssh-keygen</tt>.
	 *
	 * @param key the key to be used for signing JWTs.
	 */
	public void setSigningKey(String key) {
		Assert.hasText(key);
		key = key.trim();

		this.signingKey = key;

		if (isAssymetricKey(key)) {
			signer = new RsaSigner(key);
			logger.info("Configured with RSA signing key");
		}
		else {
			// Assume it's an HMAC key
			this.verifierKey = key;
			signer = new MacSigner(key);
		}
	}

	/**
	 * @return true if the key has a public verifier
	 */
	private boolean isAssymetricKey(String key) {
		return key.startsWith("-----BEGIN");
	}

	/**
	 * The key used for verifying signatures produced by this class. This is not used but is returned from the endpoint
	 * to allow resource servers to obtain the key.
	 *
	 * For an HMAC key it will be the same value as the signing key and does not need to be set. For and RSA key, it
	 * should be set to the String representation of the public key, in a standard format (e.g. OpenSSH keys)
	 *
	 * @param verifierKey the signature verification key (typically an RSA public key)
	 */
	public void setVerifierKey(String verifierKey) {
		boolean valid = false;
		try {
			new RsaSigner(verifierKey);
		}
		catch (Exception expected) {
			// Expected
			valid = true;
		}
		if (!valid) {
			throw new IllegalArgumentException("Private key cannot be set as verifierKey property");
		}
		this.verifierKey = verifierKey;
	}

}
