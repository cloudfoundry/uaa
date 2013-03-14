package org.cloudfoundry.identity.uaa.config;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.util.Assert;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

/**
 * @author Luke Taylor
 */
public class YamlConfigurationValidator implements ApplicationContextAware {
	private static final Log logger = LogFactory.getLog(YamlConfigurationValidator.class);

	private ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();

	private Constructor constructor;

	/**
	 * Sets a validation constructor which will be applied to the YAML doc to see whether it matches
	 * the expected Javabean.
	 */
	public YamlConfigurationValidator(Constructor constructor) {
		Assert.notNull(constructor);
		this.constructor = constructor;
	}

	@Override
	@SuppressWarnings("unchecked")
	public void setApplicationContext(ApplicationContext ctx) throws BeansException {
		Validator validator = validatorFactory.getValidator();
		try {
			String yaml = ctx.getEnvironment().getRequiredProperty("__rawYaml");

			logger.trace("Yaml document is\n" + yaml);
			Object bean = (new Yaml(constructor)).load(yaml);
			Set<ConstraintViolation<Object>> errors = validator.validate(bean);

			if (!errors.isEmpty()) {
				logger.error("YAML configuration failed validation");
				for (ConstraintViolation error: errors) {
					logger.error(error.getPropertyPath() + ": " + error.getMessage());
				}
			}
		} catch (Exception e) {
			logger.error("Failed to load YAML validation bean. Your YAML file may be invalid.", e);
		}
	}
}
