/*
 * Copyright 2006-2011 the original author or authors.
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
package org.cloudfoundry.identity.uaa.error;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.JsonToken;
import org.codehaus.jackson.map.DeserializationContext;
import org.codehaus.jackson.map.JsonDeserializer;

/**
 * @author Dave Syer
 * 
 */
public class UaaExceptionDeserializer extends JsonDeserializer<UaaException> {

	@Override
	public UaaException deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException,
			JsonProcessingException {
		
		int status = 400;

		JsonToken t = jp.getCurrentToken();
		if (t == JsonToken.START_OBJECT) {
			t = jp.nextToken();
		}
		Map<String, String> errorParams = new HashMap<String, String>();
		for (; t == JsonToken.FIELD_NAME; t = jp.nextToken()) {
			// Must point to field name
			String fieldName = jp.getCurrentName();
			// And then the value...
			t = jp.nextToken();
			// Note: must handle null explicitly here; value deserializers won't
			String value;
			if (t == JsonToken.VALUE_NULL) {
				value = null;
			}
			else {
				value = jp.getText();
				if (fieldName.equals("status")) {
					try {
						status = Integer.valueOf(value);
					} catch (NumberFormatException e) {
						// ignore
					}
				}
			}
			errorParams.put(fieldName, value);
		}

		String errorCode = errorParams.get("error");
		String errorMessage = errorParams.containsKey("error_description") ? errorParams.get("error_description")
				: null;
		if (errorMessage == null) {
			errorMessage = errorCode == null ? "UAA Error" : errorCode;
		}

		UaaException ex = new UaaException(errorCode, errorMessage, status);

		Set<Map.Entry<String, String>> entries = errorParams.entrySet();
		for (Map.Entry<String, String> entry : entries) {
			String key = entry.getKey();
			if (!"error".equals(key) && !"error_description".equals(key) && !"status".equals(key)) {
				ex.addAdditionalInformation(key, entry.getValue());
			}
		}

		return ex;

	}
}
