package org.cloudfoundry.identity.uaa.impl.config;

import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import io.awspring.cloud.core.SpringCloudClientConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.YAMLException;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import java.util.*;

public class AwsSecretsLoader {

    private static final Logger LOGGER = LoggerFactory.getLogger(AwsSecretsLoader.class);

    public List<Resource> createResourcesFromSecrets(final ConfigurableEnvironment environment) {
        String awsSecretNames = environment.getProperty("AWS_SECRET_MANAGER_NAMES");
        if (StringUtils.hasText(awsSecretNames)) {
            String[] secretNames = awsSecretNames.split(";");
            AWSSecretsManager secretManagerClient = awsSecretsManager();
            List<Resource> resources = new ArrayList<>();
            Arrays.stream(secretNames).forEach(secretName -> {
                try {
                    LOGGER.info("Loading secrets from AWS Secret Manager for Secret Name {}", secretName);
                    GetSecretValueResult results =
                            secretManagerClient.getSecretValue(new GetSecretValueRequest().withSecretId(secretName));
                    String secretString = results.getSecretString();
                    if (StringUtils.hasText(secretString) && isValidYamlString(secretName, secretString)) {
                        Resource resource = new ByteArrayResource(secretString.getBytes(), secretName);
                        resources.add(resource);
                    }
                } catch (Exception e) {
                    LOGGER.error("Unable to load secrets from AWS Secret Manager for Secret Name {}", secretName, e);
                }
            });
            return resources;
        } else {
            LOGGER.info("AWS Secret Manager is not configured");
            return null;
        }
    }

    protected AWSSecretsManager awsSecretsManager() {
        return AWSSecretsManagerClientBuilder.standard().withClientConfiguration(
                SpringCloudClientConfiguration.getClientConfiguration()).build();
    }

    private boolean isValidYamlString(final String secretName, final String yamlString) {
        try {
            // Validations using UaaConfiguration.class can not be done because it validates and requires all fields/
            // elements of UaaConfiguration.class(marked with javax.validation.* annotations) but only few elements
            // (sensitive credentials) are loaded from aws secret manager so just perform basic YAML format validations.
            Yaml yaml = new Yaml();
            Map<String, Object> map = yaml.load(yamlString);
            Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
            Set<ConstraintViolation<Map<String, Object>>> errors = validator.validate(map);
            if (!errors.isEmpty()) {
                LOGGER.error("YAML configuration from AWS Secret Manager failed validations");
                for (ConstraintViolation<?> error : errors) {
                    LOGGER.error(error.getPropertyPath() + ": " + error.getMessage());
                }
                throw new YAMLException("YAML format validations failed");
            }
            return true;
        } catch (Exception e) {
            LOGGER.error("Invalid YAML content found for Secret Name {}", secretName);
            throw e;
        }
    }
}
