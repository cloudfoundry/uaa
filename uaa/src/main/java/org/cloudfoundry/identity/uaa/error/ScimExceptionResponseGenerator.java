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

import org.cloudfoundry.identity.uaa.scim.ScimException;
import org.springframework.http.ResponseEntity;

/**
 * @author Dave Syer
 *
 */
public class ScimExceptionResponseGenerator implements ResponseGenerator<ScimException> {
	
	@Override
	public boolean supports(Class<?> clazz) {
		return ScimException.class.isAssignableFrom(clazz);
	}

	@Override
	public ResponseEntity<? extends ScimException> generateResponseEntity(Object handler, ScimException t) {
		return new ResponseEntity<ScimException>(t, t.getStatus());
	}

}
