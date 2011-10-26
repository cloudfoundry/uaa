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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.collaboration.Org;
import org.cloudfoundry.identity.collaboration.Permission;
import org.cloudfoundry.identity.collaboration.User;
import org.cloudfoundry.identity.collaboration.simple.Group;
import org.cloudfoundry.identity.collaboration.simple.GroupPermission;
import org.cloudfoundry.identity.collaboration.simple.SimpleProject;
import org.cloudfoundry.identity.collaboration.simple.SimpleResource;
import org.cloudfoundry.identity.collaboration.simple.SimpleResource.Type;
import org.junit.Test;

/**
 * @author Dave Syer
 * 
 */
public class OrgTests {

	private Group noobs = new Group.Builder().name("noobs").addUser(new User("dave")).build();
	private Group gurus = new Group.Builder().name("gurus").addUser(new User("dale")).build();

	private DirectPermissionChecker checker = new DirectPermissionChecker();

	private SimpleResource foo = new Builders.ResourceBuilder(checker, "foo", Type.APPLICATIONS).build();
	private SimpleResource bar = new Builders.ResourceBuilder(checker, "bar", Type.APPLICATIONS).build();
	private SimpleResource spam = new Builders.ResourceBuilder(checker, "spam", Type.APPLICATIONS).build();
	private SimpleResource bucket = new Builders.ResourceBuilder(checker, "bucket", Type.SERVICES).build();

	private SimpleProject fooProject = new Builders.ProjectBuilder(checker).name("foo").addResource(foo)
			.addResource(bucket).addGroupPermissions(new GroupPermission(noobs, Permission.READ))
			.addGroupPermissions(new GroupPermission(gurus, Permission.WRITE)).build();
	private SimpleProject barProject = new Builders.ProjectBuilder(checker).name("bar").addResource(bar).addResource(spam)
			.addGroupPermissions(new GroupPermission(noobs, Permission.WRITE)).build();

	private Org org = new Builders.OrgBuilder(checker).name("mine").addProject(barProject).addProject(fooProject).build();

	@Test
	public void testListApps() throws Exception {
		assertEquals(4, org.getResources().size());
		assertEquals(3, org.getResources(Type.APPLICATIONS.toString()).size());
		assertEquals(1, org.getResources(Type.SERVICES.toString()).size());
	}

	@Test
	public void testPermissionWithOverlap() throws Exception {
		assertTrue(bar.isPermitted(new User("dave"), Permission.READ));
		assertTrue(bar.isPermitted(new User("dave"), Permission.WRITE));
		assertTrue(bucket.isPermitted(new User("dave"), Permission.READ));
		// bucket is not in barGroup, where dave has WRITE permission
		assertFalse(bucket.isPermitted(new User("dave"), Permission.WRITE));
	}

}
