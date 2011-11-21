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

package org.cloudfoundry.identity.uaa.authentication;

import java.beans.PropertyEditorSupport;

import org.springframework.util.StringUtils;

/**
 * @author Dave Syer
 *
 */
public class PromptEditor extends PropertyEditorSupport {

	@Override
	public void setAsText(String text) throws IllegalArgumentException {
		if (StringUtils.hasText(text)) {
			setValue(Prompt.valueOf(text));
		}
		else {
			setValue(null);
		}
	}

	@Override
	public String getAsText() {
		Prompt value = (Prompt) getValue();
		return (value != null ? value.toString() : "");
	}

}
