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

package org.cloudfoundry.identity.collaboration.session;

import java.util.UUID;

import org.cloudfoundry.identity.collaboration.Permission;
import org.cloudfoundry.identity.collaboration.Resource;
import org.cloudfoundry.identity.collaboration.User;

/**
 * @author Dave Syer
 * 
 */
public class Session {

	private final Target target;
	private final User puppet;
	private final User master;
	
	private final String id = UUID.randomUUID().toString();

	public Session(User puppet, User master, Target target) {
		this.puppet = puppet;
		this.master = master;
		this.target = target;
		if (!master.equals(puppet) && !target.isPermittedToDelegate(master)) {
			throw new IllegalArgumentException(String.format("%s is not allowed to delegate in %s", master, target));
		}
	}
	
	public Session(User user, Target target) {
		this(user, user, target);
	}
	
	public String getId() {
		return id;
	}

	public Target getTarget() {
		return target;
	}

	public User getPuppet() {
		return puppet;
	}

	public User getMaster() {
		return master;
	}

	public boolean isPermitted(Resource resource, Permission permission) {
		return target.isPermitted(resource, puppet, permission);
	}

}
