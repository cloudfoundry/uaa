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

package org.cloudfoundry.identity.collaboration.simple.direct;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.collaboration.Permission;
import org.cloudfoundry.identity.collaboration.Project;
import org.cloudfoundry.identity.collaboration.User;
import org.cloudfoundry.identity.collaboration.simple.Group;
import org.cloudfoundry.identity.collaboration.simple.GroupPermission;
import org.cloudfoundry.identity.collaboration.simple.SimpleProject;
import org.cloudfoundry.identity.collaboration.simple.SimpleResource;
import org.cloudfoundry.identity.collaboration.simple.SimpleResource.Type;
import org.cloudfoundry.identity.collaboration.simple.direct.Builders;
import org.cloudfoundry.identity.collaboration.simple.direct.DirectPermissionChecker;
import org.junit.Test;

/**
 * @author Dave Syer
 * 
 */
public class ProjectTests {

	private User dave = new User("dave");
	private User dale = new User("dale");

	private Group readers = new Group.Builder().name("readers").addUser(dave).addUser(dale).build();
	private Group writers = new Group.Builder().name("writers").addUser(dale).build();

	private DirectPermissionChecker checker = new DirectPermissionChecker();

	private SimpleResource bar = new Builders.ResourceBuilder(checker, "bar", Type.APPLICATIONS).build();

	private SimpleProject project = new Builders.ProjectBuilder(checker).name("foo").addResource(bar)
			.addGroupPermissions(new GroupPermission(readers, Permission.READ))
			.addGroupPermissions(new GroupPermission(writers, Permission.WRITE)).build();

	@Test
	public void testPermissionForResource() throws Exception {
		assertTrue(bar.isPermitted(dave, Permission.READ));
	}

	@Test
	public void testPermissionForCreate() throws Exception {
		assertFalse(project.isPermitted(dave, Permission.WRITE));
		// Dale is a reader and a writer, so we want to make sure the writer permssion wins
		assertTrue(project.isPermitted(dale, Permission.WRITE));
	}

	@Test
	public void testUserPermission() throws Exception {
		SimpleResource bar = new Builders.ResourceBuilder(checker, "bar", Type.APPLICATIONS).build();
		Project project = new Builders.ProjectBuilder(checker).name("foo").addResource(bar)
				.addUserPermissions(dave, Permission.READ)
				.addGroupPermissions(new GroupPermission(writers, Permission.WRITE)).build();
		assertTrue(bar.isPermitted(dave, Permission.READ));
		assertTrue(project.isPermitted(dave, Permission.READ));
	}

}
