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
package org.cloudfoundry.identity.uaa.config;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.beans.factory.FactoryBean;

/**
 * @author Dave Syer
 * 
 */
public class UaaUserMapFactoryBean implements FactoryBean<Map<String, UaaUser>> {

	private final Collection<UaaUser> users;
	private int count = 0;

	public UaaUserMapFactoryBean(Collection<UaaUser> users) {
		this.users = users;
	}

	@Override
	public Map<String, UaaUser> getObject() throws Exception {
		Map<String, UaaUser> map = new HashMap<String, UaaUser>();
		for (UaaUser user : users) {
			UaaUser value = user.id(count++);
			map.put(value.getUsername(), value);
		}
		return map ;
	}

	@Override
	public Class<?> getObjectType() {
		return Map.class;
	}

	@Override
	public boolean isSingleton() {
		return true;
	}

}
