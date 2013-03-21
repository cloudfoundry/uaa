package org.cloudfoundry.identity.uaa;

import javax.validation.ConstraintViolationException;

import org.cloudfoundry.identity.uaa.config.YamlConfigurationValidator;
import org.junit.Test;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.core.env.StandardEnvironment;

/**
 * @author Luke Taylor
 */
public class UaaConfigurationTests {

	private void createValidator(final String yaml) throws Exception {
		StaticApplicationContext ctx = new StaticApplicationContext();
		StandardEnvironment env = new StandardEnvironment() {
			@Override
			public String getRequiredProperty(String key) {
				if (key.equals("__rawYaml")) {
					return yaml;
				}
				return super.getRequiredProperty(key);
			}
		};
		ctx.setEnvironment(env);
		YamlConfigurationValidator validator = new YamlConfigurationValidator(new UaaConfiguration.UaaConfigConstructor());
		validator.setExceptionIfInvalid(true);
		validator.setApplicationContext(ctx);
		validator.afterPropertiesSet();
	}

	@Test
	public void validYamlIsOk() throws Exception {
		createValidator(
			"name: uaa\n" +
			"oauth:\n" +
			"  clients:\n" +
			"    vmc:\n" +
			"      id: vmc\n" +
			"      authorized-grant-types: implicit\n");
	}

	@Test(expected = ConstraintViolationException.class)
	public void invalidIssuerUriCausesException() throws Exception {
		createValidator("name: uaa\nissuer.uri: notauri\n");
	}
}
