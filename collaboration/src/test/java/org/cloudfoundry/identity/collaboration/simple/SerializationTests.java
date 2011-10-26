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

import static org.junit.Assert.assertEquals;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Collection;
import java.util.HashSet;

import org.cloudfoundry.identity.collaboration.Project;
import org.cloudfoundry.identity.collaboration.Resource;
import org.cloudfoundry.identity.collaboration.simple.SimpleResource.Type;
import org.cloudfoundry.identity.collaboration.simple.direct.Builders;
import org.cloudfoundry.identity.collaboration.simple.direct.DirectPermissionChecker;
import org.codehaus.jackson.annotate.JsonCreator;
import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.annotate.JsonDeserialize;
import org.junit.Ignore;
import org.junit.Test;

/**
 * @author Dave Syer
 * 
 */
public class SerializationTests {

	@Test
	@Ignore
	public void testRoundTripWithGroup() throws Exception {

		ObjectMapper mapper = new ObjectMapper();
		mapper.getDeserializationConfig().addMixInAnnotations(SimpleResource.class, SimpleResourceHelper.class);
		mapper.getDeserializationConfig().addMixInAnnotations(Project.class, ProjectHelper.class);

		DirectPermissionChecker checker = new DirectPermissionChecker();
		Project project = new Builders.ProjectBuilder(checker).name("foo")
				.addResource(new SimpleResource("bar", Type.APPLICATIONS, checker)).build();

		StringWriter out = new StringWriter();

		mapper.writeValue(out, project);
		System.err.println(out);
		assertEquals(project, mapper.readValue(new StringReader(out.toString()), Project.class));

	}

	@JsonIgnoreProperties("type")
	@JsonDeserialize(as = SimpleProject.class)
	private static abstract class ProjectHelper {
		@SuppressWarnings("unused")
		@JsonCreator
		public static Project create(
				@JsonProperty("name") String name,
				@JsonDeserialize(contentAs = SimpleResource.class, as = HashSet.class) @JsonProperty("resources") Collection<Resource> resources) {
			return new SimpleProject(name, resources, null);
		}
	}

	private abstract static class SimpleResourceHelper {
		@SuppressWarnings("unused")
		public SimpleResourceHelper(@JsonProperty("name") String name, @JsonProperty("type") Type type) {
		}
	}

}
