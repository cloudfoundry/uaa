/*
 * Copyright 2012-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.cloudfoundry.identity.uaa.cypto;

/**
 * @author Haytham Mohamed
 **/

public class EncryptionKey {
	private String label, passphrase;

	public String getLabel() {
		return label;
	}

	public void setLabel(String label) {
		this.label = label;
	}

	public String getPassphrase() {
		return passphrase;
	}

	public void setPassphrase(String passphrase) {
		this.passphrase = passphrase;
	}

	public byte[] encrypt(String plaintext) throws EncryptionServiceException {
		Encryption encryption = new Encryption();
		return encryption.encrypt(plaintext, this.getPassphrase());
	}

	public byte[] decrypt(byte[] encrypt) throws EncryptionServiceException {
		Encryption encryption = new Encryption();
		return encryption.decrypt(encrypt, this.getPassphrase());
	}

}
