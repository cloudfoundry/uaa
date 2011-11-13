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

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;

/**
 * @author Dave Syer
 *
 */
public class DefaultExceptionResponseGenerator implements ResponseGenerator<Exception> {

	private HttpStatus statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
	
	/**
	 * @param statusCode the statusCode to set
	 */
	public void setStatusCode(HttpStatus statusCode) {
		this.statusCode = statusCode;
	}
	
	@Override
	public boolean supports(Class<?> clazz) {
		return !AccessDeniedException.class.isAssignableFrom(clazz) && ! AuthenticationException.class.isAssignableFrom(clazz);
	}

	@Override
	public ResponseEntity<? extends Exception> generateResponseEntity(Object handler, Exception t) {
		return new ResponseEntity<Exception>(t, statusCode);
	}

}
