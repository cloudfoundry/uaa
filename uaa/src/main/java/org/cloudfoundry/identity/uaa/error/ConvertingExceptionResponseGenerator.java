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
package org.cloudfoundry.identity.uaa.error;

import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.scim.ScimException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * @author Dave Syer
 * 
 */
public class ConvertingExceptionResponseGenerator implements ResponseGenerator<Exception> {
	
	private Map<Class<? extends Exception>, HttpStatus> statuses = new HashMap<Class<? extends Exception>, HttpStatus>();
	
	/**
	 * Map from exception type to Http status.
	 * 
	 * @param statuses the statuses to set
	 */
	public void setStatuses(Map<Class<? extends Exception>, HttpStatus> statuses) {
		this.statuses = statuses;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		for (Class<?> key : statuses.keySet()) {
			if (key.isAssignableFrom(clazz)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public ResponseEntity<? extends Exception> generateResponseEntity(Object handler, Exception t) {
		ScimException e = new ScimException("Unexpected error", t, HttpStatus.INTERNAL_SERVER_ERROR);
		Class<?> clazz = t.getClass();
		for (Class<?> key : statuses.keySet()) {
			if (key.isAssignableFrom(clazz)) {
				e = new ScimException(t.getMessage(), t, statuses.get(key));
			}
		}
		return new ResponseEntity<ScimException>(e, e.getStatus());
	}

}
