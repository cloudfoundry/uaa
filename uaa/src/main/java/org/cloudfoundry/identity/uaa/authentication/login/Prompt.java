/*
 * Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package org.cloudfoundry.identity.uaa.authentication.login;

import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 *
 */
public class Prompt {

	private final String name;
	private final String text;
	private final String type;

	public Prompt(String name, String type, String text) {
		this.name = name;
		this.type = type;
		this.text = text;
	}

	public String getName() {
		return name;
	}

	public String[] getDetails() {
		return new String[] {type, text};
	}

	public static Prompt valueOf(String text) {
		if (!StringUtils.hasText(text)) {
			return null;
		}
		String[] parts = text.split(":");
		if (parts.length<2) {
			return null;
		}
		String name = parts[0].replaceAll("\"", "");
		String[] values = parts[1].replaceAll("\"", "").replaceAll("\\[", "").replaceAll("\\]", "").split(",");
		values = StringUtils.trimArrayElements(values);
		return new Prompt(name, values[0], values[1]);
	}

	@Override
	public String toString() {
		return String.format("\"%s\":[\"%s\",\"%s\"]", name, type, text);
	}
	
	@Override
	public int hashCode() {
		return 31 + toString().hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Prompt other = (Prompt) obj;
		return toString().equals(other.toString());
	}
	
	

}
