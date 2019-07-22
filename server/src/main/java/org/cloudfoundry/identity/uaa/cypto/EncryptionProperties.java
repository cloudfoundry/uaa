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

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @author Haytham Mohamed
 **/

@ConfigurationProperties(prefix = "encryption")
public class EncryptionProperties {

	private String activeKeyLabel;
	private List<EncryptionKey> encryptionKeys;

	public void setEncryptionKeys(List<EncryptionKey> keys) {
		this.encryptionKeys = keys;
	}

	public List<EncryptionKey> getEncryptionKeys() {
		return this.encryptionKeys;
	}

	public void setActiveKeyLabel(String str) { this.activeKeyLabel = str; }

	public String getActiveKeyLabel() { return activeKeyLabel; }


}
