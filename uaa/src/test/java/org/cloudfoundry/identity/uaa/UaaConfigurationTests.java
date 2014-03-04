package org.cloudfoundry.identity.uaa;

import static org.junit.Assert.assertTrue;

import javax.validation.ConstraintViolationException;

import org.cloudfoundry.identity.uaa.config.YamlConfigurationValidator;
import org.junit.Test;

/**
 * @author Luke Taylor
 */
public class UaaConfigurationTests {

	private YamlConfigurationValidator<UaaConfiguration> validator = new YamlConfigurationValidator<UaaConfiguration>(new UaaConfiguration.UaaConfigConstructor());

	private void createValidator(final String yaml) throws Exception {
		validator.setExceptionIfInvalid(true);
		validator.setYaml(yaml);
		validator.afterPropertiesSet();
	}

	@Test
	public void validYamlIsOk() throws Exception {
		createValidator(
			"name: uaa\n" +
			"issuer.uri: http://foo.com\n" +
			"oauth:\n" +
			"  clients:\n" +
			"    vmc:\n" +
			"      id: vmc\n" +
			"      authorized-grant-types: implicit\n");
	}

	@Test
	public void validClientIsOk() throws Exception {
		createValidator(
			"oauth:\n" +
			"  clients:\n" +
			"    vmc:\n" +
			"      id: vmc\n" +
			"      autoapprove: true\n" +
			"      authorized-grant-types: implicit\n");
		assertTrue(validator.getObject().oauth.clients.containsKey("vmc"));
	}

	@Test(expected = ConstraintViolationException.class)
	public void invalidIssuerUriCausesException() throws Exception {
		createValidator("name: uaa\nissuer.uri: notauri\n");
	}
}
