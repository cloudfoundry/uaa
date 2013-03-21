package org.cloudfoundry.identity.uaa.config;

import javax.validation.*;
import java.util.Collections;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.util.Assert;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.error.YAMLException;

/**
 * Uses a defined SnakeYAML constructor to validate the "__rawYaml" property
 * obtained from the environment.
 *
 * @author Luke Taylor
 */
public class YamlConfigurationValidator implements ApplicationContextAware, InitializingBean {
	private static final Log logger = LogFactory.getLog(YamlConfigurationValidator.class);

	private Constructor constructor;
	private boolean exceptionIfInvalid;
	private ApplicationContext ctx;

	/**
	 * Sets a validation constructor which will be applied to the YAML doc to see whether it matches
	 * the expected Javabean.
	 */
	public YamlConfigurationValidator(Constructor constructor) {
		Assert.notNull(constructor);
		this.constructor = constructor;
	}

	@SuppressWarnings("unchecked")
	public void setApplicationContext(ApplicationContext ctx) throws ValidationException, YAMLException {
		this.ctx = ctx;
	}

	public void setExceptionIfInvalid(boolean exceptionIfInvalid) {
		this.exceptionIfInvalid = exceptionIfInvalid;
	}

	@SuppressWarnings("unchecked")
	public void afterPropertiesSet() throws Exception {
		Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

		try {
			String yaml = ctx.getEnvironment().getRequiredProperty("__rawYaml");

			logger.trace("Yaml document is\n" + yaml);
			Set<ConstraintViolation<Object>> errors = validator.validate((new Yaml(constructor)).load(yaml));

			if (!errors.isEmpty()) {
				logger.error("YAML configuration failed validation");
				for (ConstraintViolation error: errors) {
					logger.error(error.getPropertyPath() + ": " + error.getMessage());
				}
				if (exceptionIfInvalid) {
					throw new ConstraintViolationException((Set)errors);
				}
			}
		} catch (YAMLException e) {
			if (exceptionIfInvalid) {
				throw e;
			}
			logger.error("Failed to load YAML validation bean. Your YAML file may be invalid.", e);
		}
	}
}
