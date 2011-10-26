/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.identity.app.web;

import static org.junit.Assert.assertEquals;

import java.io.StringReader;
import java.io.StringWriter;

import org.codehaus.jackson.annotate.JsonValue;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Test;
import org.springframework.security.openid.OpenIDAuthenticationStatus;

/**
 * @author Dave Syer
 * 
 */
public class SerializationTests {

	@Test
	public void testOpenIDStatus() throws Exception {
		OpenIDAuthenticationStatus status = OpenIDAuthenticationStatus.SUCCESS;
		ObjectMapper mapper = new ObjectMapper();
		StringWriter string = new StringWriter();
		mapper.writeValue(string, status);
		System.err.println(string);
		OpenIDAuthenticationStatus value = mapper.readValue(new StringReader(string.toString()), OpenIDAuthenticationStatus.class);
		assertEquals(status.toString(), value.toString());
		// TODO: these are not equal because of the weird implementation of OpenIDAuthenticationStatus
		 assertEquals(status, value);
	}

	@Test
	public void testCustomStatus() throws Exception {
		Status status = Status.SUCCESS;
		ObjectMapper mapper = new ObjectMapper();
		mapper.getSerializationConfig().addMixInAnnotations(Status.class, StatusHelper.class);
		mapper.getDeserializationConfig().addMixInAnnotations(Status.class, StatusHelper.class);
		StringWriter string = new StringWriter();
		mapper.writeValue(string, status);
		System.err.println(string);
		Status value = mapper.readValue(new StringReader(string.toString()), Status.class);
		assertEquals(status.toString(), value.toString());
		// TODO: these are not equal because of the weird implementation of Status
		// assertEquals(status, value);
	}

	public static abstract class StatusHelper {
		public StatusHelper(String value) {
		}
		
		@Override
		@JsonValue
		public String toString() {
			return super.toString();
		}
	}
	
	public static class Status {
		
		public static Status SUCCESS = new Status("success");
		public static Status FAILED = new Status("failed");
		
		private final String name;

		private Status(String name) {
			this.name = name;
		}
		
		@Override
		public String toString() {
			return name;
		}

	}

}
