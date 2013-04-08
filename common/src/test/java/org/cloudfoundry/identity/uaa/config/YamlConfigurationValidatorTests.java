package org.cloudfoundry.identity.uaa.config;

import static org.junit.Assert.assertEquals;

import javax.validation.ConstraintViolationException;
import javax.validation.constraints.NotNull;

import org.junit.Test;
import org.yaml.snakeyaml.error.YAMLException;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class YamlConfigurationValidatorTests {
	
	private YamlConfigurationValidator<Foo> validator;

	private Foo createFoo(final String yaml) throws Exception {
		validator = new YamlConfigurationValidator<Foo>(new FooConstructor());
		validator.setYaml(yaml);
		validator.setExceptionIfInvalid(true);
		validator.afterPropertiesSet();
		return validator.getObject();
	}

	@Test
	public void validYamlLoadsWithNoErrors() throws Exception {
		Foo foo = createFoo("foo-name: blah\nbar: blah");
		assertEquals("blah", foo.bar);
	}

	@Test(expected = YAMLException.class)
	public void unknownPropertyCausesLoadFailure() throws Exception {
		createFoo("hi: hello\nname: foo\nbar: blah");
	}

	@Test(expected = ConstraintViolationException.class)
	public void missingPropertyCausesValidationError() throws Exception {
		createFoo("bar: blah");
	}

	private static class Foo {
		@NotNull
		public String name;
		public String bar;
	}

	private static class FooConstructor extends CustomPropertyConstructor {

		public FooConstructor() {
			super(Foo.class);
			addPropertyAlias("foo-name", Foo.class, "name");
		}
	}
}
