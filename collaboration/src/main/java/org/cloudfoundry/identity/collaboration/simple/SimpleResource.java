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

package org.cloudfoundry.identity.collaboration.simple;

import org.cloudfoundry.identity.collaboration.Resource;

/**
 * @author Dave Syer
 * 
 */
public class SimpleResource extends BaseResource implements Resource {
	
	public static enum Type {APPLICATIONS, SERVICES};

	public SimpleResource(String name, Type type) {
		this(name, type, null);
	}

	public SimpleResource(String name, Type type, PermissionChecker checker) {
		this(name, type.toString().toLowerCase(), checker);
	}
		
	public SimpleResource(String name, String type, PermissionChecker checker) {
		super(name, type, checker);
	}
	
	@Override
	public Nature getNature() {
		return Nature.LEAF;
	}

}
