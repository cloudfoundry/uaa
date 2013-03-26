package org.cloudfoundry.identity.uaa.config;

import javax.validation.ConstraintViolationException;
import javax.validation.constraints.NotNull;

import org.junit.Test;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.StandardEnvironment;
import org.yaml.snakeyaml.error.YAMLException;

/**
 * @author Luke Taylor
 */
public class YamlConfigurationValidatorTests {
	YamlConfigurationValidator validator;

	private void createValidator(final String yaml) throws Exception {
		StaticApplicationContext ctx = new StaticApplicationContext();
		ConfigurableEnvironment env = new StandardEnvironment() {
			@Override
			public String getRequiredProperty(String key) {
				if (key.equals("__rawYaml")) {
					return yaml;
				}
				return super.getRequiredProperty(key);
			}
		};
		ctx.setEnvironment(env);
		validator = new YamlConfigurationValidator(new FooConstructor());
		validator.setExceptionIfInvalid(true);
		validator.setApplicationContext(ctx);
		validator.afterPropertiesSet();
	}

	@Test
	public void validYamlLoadsWithNoErrors() throws Exception {
		createValidator("foo-name: blah\nbar: blah");
	}

	@Test(expected = YAMLException.class)
	public void unknownPropertyCausesLoadFailure() throws Exception {
		createValidator("hi: hello\nname: foo\nbar: blah");
	}

	@Test(expected = ConstraintViolationException.class)
	public void missingPropertyCausesValidationError() throws Exception {
		createValidator("bar: blah");
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
