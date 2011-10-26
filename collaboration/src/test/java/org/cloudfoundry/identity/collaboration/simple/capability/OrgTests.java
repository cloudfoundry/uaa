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

package org.cloudfoundry.identity.collaboration.simple.capability;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;

import org.cloudfoundry.identity.collaboration.Org;
import org.cloudfoundry.identity.collaboration.Permission;
import org.cloudfoundry.identity.collaboration.Project;
import org.cloudfoundry.identity.collaboration.Resource;
import org.cloudfoundry.identity.collaboration.User;
import org.cloudfoundry.identity.collaboration.simple.Group;
import org.cloudfoundry.identity.collaboration.simple.SimpleOrg;
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

	private CapabilityPermissionChecker checker = new CapabilityPermissionChecker();

	private Resource foo = new SimpleResource("foo", Type.APPLICATIONS, checker);
	private Resource bar = new SimpleResource("bar", Type.APPLICATIONS, checker);
	private Resource spam = new SimpleResource("spam", Type.APPLICATIONS, checker);
	private Resource bucket = new SimpleResource("bucket", Type.SERVICES, checker);

	private Project poo = new SimpleProject("poo", Arrays.asList(foo, bucket), checker);
	private Project par = new SimpleProject("par", Arrays.asList(bar, spam), checker);

	private Org org = new SimpleOrg("mine", Arrays.asList(par,poo), checker);

	{
		checker.addCapability(org, noobs, new Capability("bucketReaders", "/poo/services/bucket", Permission.READ));
		checker.addCapability(org, gurus, new Capability("globalWriters", "/", Permission.WRITE));
		checker.addCapability(org, noobs, new Capability("parWriters", "/par", Permission.WRITE));
	}

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

	@Test
	public void testSensibleDefaultsForLegacyUser() throws Exception {
		User dave = new User("dave");
		Project daves = new SimpleProject(dave.getName(), Collections.<Resource>emptySet(), checker);
		assertTrue(daves.isPermitted(dave, Permission.READ));
		assertTrue(daves.isPermitted(dave, Permission.WRITE));
	}

}
