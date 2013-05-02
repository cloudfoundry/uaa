package org.cloudfoundry.identity.uaa;

import javax.validation.ConstraintViolationException;

import org.cloudfoundry.identity.uaa.config.YamlConfigurationValidator;
import org.junit.Test;

/**
 * @author Luke Taylor
 */
public class UaaConfigurationTests {

	private void createValidator(final String yaml) throws Exception {
		YamlConfigurationValidator<UaaConfiguration> validator = new YamlConfigurationValidator<UaaConfiguration>(new UaaConfiguration.UaaConfigConstructor());
		validator.setExceptionIfInvalid(true);
		validator.setYaml(yaml);
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
