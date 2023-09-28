package org.cloudfoundry.identity.uaa.impl.config;

import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.GenericConverter;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.support.StandardServletEnvironment;
import org.yaml.snakeyaml.Yaml;

import javax.servlet.ServletContext;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AwsSecretsLoaderTest {

    private AwsSecretsLoader awsSecretsLoader;
    private StandardServletEnvironment environment;
    private AWSSecretsManager awsSecretsManager;
    private YamlServletProfileInitializer initializer;
    private ConfigurableWebApplicationContext context;
    private ServletContext servletContext;

    private static final String TEST_SECRET_NAME_1 = "/dummy-non-existing-aws-secret-manager-secret/test-secret-1";
    private static final String TEST_SECRET_NAME_2 = "/dummy-non-existing-aws-secret-manager-secret/test-secret-2";
    private static final String TEST_KEY_1 = "test-key-1";
    private static final String TEST_VALUE_1 = "test-value-1";
    private static final String TEST_KEY_2 = "test-key-2";
    private static final String TEST_VALUE_2 = "test-value-2";
    private static final String TEST_KEY_3 = "activeKeyId";
    private static final String TEST_VALUE_3 = "key-id-1";
    private static final String TEST_KEY_4 = "keys";
    private static final String TEST_VALUE_4_SIGNING_KEY = "----dummy-signing-key----";
    private static final String TEST_KEY_5 = "oauth";
    private static final String TEST_VALUE_5_CLIENT_1 = "client-1";
    private static final String TEST_VALUE_5_CLIENT_1_SECRET = "client-1-secret";
    private static final String TEST_VALUE_5_CLIENT_2 = "client-2";
    private static final String TEST_VALUE_5_CLIENT_2_SECRET = "client-2-secret";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @BeforeEach
    void setup() {
        awsSecretsLoader = spy(AwsSecretsLoader.class);
        environment = new StandardServletEnvironment();
        awsSecretsManager = mock(AWSSecretsManager.class);
        initializer = spy(YamlServletProfileInitializer.class);
        context = mock(ConfigurableWebApplicationContext.class);
        servletContext = mock(ServletContext.class);

        doReturn(servletContext).when(context).getServletContext();
        doReturn(environment).when(context).getEnvironment();
        doReturn("/context").when(servletContext).getContextPath();
    }

    @AfterEach
    void cleanup() {
        // Clear aws secret manager secret names
        System.clearProperty("AWS_SECRET_MANAGER_NAMES");
    }

    String vaidYamlString() {
        String yamlString = TEST_KEY_1 + ": " + TEST_VALUE_1 + "\n" +
                TEST_KEY_2 + ": " + TEST_VALUE_2 + "\n" +
                TEST_KEY_3 + ": " + TEST_VALUE_3 + "\n" +
                TEST_KEY_4 + ":\n" +
                "  key-id-1:\n" +
                "    signingKey: " + TEST_VALUE_4_SIGNING_KEY + "\n" +
                TEST_KEY_5 + ":\n" +
                "  clients:\n" +
                "    " + TEST_VALUE_5_CLIENT_1 + ":\n" +
                "      secret: " + TEST_VALUE_5_CLIENT_1_SECRET + "\n" +
                "    " + TEST_VALUE_5_CLIENT_2 + ":\n" +
                "      secret: " + TEST_VALUE_5_CLIENT_2_SECRET;
        return yamlString;
    }

    @Test
    void testCreateResourcesFromSingleSecretName() {
        System.setProperty("AWS_SECRET_MANAGER_NAMES", TEST_SECRET_NAME_1);
        mockSecretManagerCalls();
        List<Resource> resources = awsSecretsLoader.createResourcesFromSecrets(environment);
        assertNotNull(resources);
        assertTrue(resources.size() == 1);
        assertTrue(resources.get(0).getDescription().contains(TEST_SECRET_NAME_1));
        verify(awsSecretsLoader, times(1)).awsSecretsManager();
    }

    @Test
    void testCreateResourcesFromMultipleSecretName() {
        System.setProperty("AWS_SECRET_MANAGER_NAMES", TEST_SECRET_NAME_1 + ";" + TEST_SECRET_NAME_2);
        mockSecretManagerCalls();
        List<Resource> resources = awsSecretsLoader.createResourcesFromSecrets(environment);
        assertNotNull(resources);
        assertTrue(resources.size() == 2);
        assertTrue(resources.get(0).getDescription().contains(TEST_SECRET_NAME_1));
        assertTrue(resources.get(1).getDescription().contains(TEST_SECRET_NAME_2));
        verify(awsSecretsLoader, times(1)).awsSecretsManager();
    }

    @Test
    void testCreateResourcesWithoutSecretName() {
        assertNull(environment.getProperty("AWS_SECRET_MANAGER_NAMES"));
        mockSecretManagerCalls();
        List<Resource> resources = awsSecretsLoader.createResourcesFromSecrets(environment);
        assertNull(resources);
        verify(awsSecretsLoader, times(0)).awsSecretsManager();
    }

    @Test
    void testCreateResourcesWithEmptySecretName() {
        System.setProperty("AWS_SECRET_MANAGER_NAMES", "");
        mockSecretManagerCalls();
        List<Resource> resources = awsSecretsLoader.createResourcesFromSecrets(environment);
        assertNull(resources);
        verify(awsSecretsLoader, times(0)).awsSecretsManager();
    }

    @Test
    void testCreateResourcesWithWhitespaceInSecretName() {
        System.setProperty("AWS_SECRET_MANAGER_NAMES", "    ");
        mockSecretManagerCalls();
        List<Resource> resources = awsSecretsLoader.createResourcesFromSecrets(environment);
        assertNull(resources);
        verify(awsSecretsLoader, times(0)).awsSecretsManager();
    }

    @Test
    void testEnvironmentVariablesLoadedFromSecretName() throws JsonProcessingException {

        // Set aws secret manager secret names
        System.setProperty("AWS_SECRET_MANAGER_NAMES", TEST_SECRET_NAME_1 + ";" + TEST_SECRET_NAME_2);

        // Assert test keys not present in environment
        assertNull(environment.getProperty(TEST_KEY_1));
        assertNull(environment.getProperty(TEST_KEY_2));
        assertNull(environment.getProperty(TEST_KEY_3));
        assertNull(environment.getProperty(TEST_KEY_4));
        assertNull(environment.getProperty(TEST_KEY_5));

        // Mock AwsSecretsLoader constructor(new AwsSecretsLoader()) call and this mocking is limited to below try block
        try (MockedConstruction<AwsSecretsLoader> myobjectMockedConstruction =
                     Mockito.mockConstruction(AwsSecretsLoader.class, (mock, context) -> {
                         doReturn(resources()).when(mock).createResourcesFromSecrets(environment);
                     })) {

            addConvertor(environment);
            initializer.initialize(context);

            // Assert test keys are present in environment after loading secrets
            assertEquals(TEST_VALUE_1, environment.getProperty(TEST_KEY_1));
            assertEquals(TEST_VALUE_2, environment.getProperty(TEST_KEY_2));
            assertEquals(TEST_VALUE_3, environment.getProperty(TEST_KEY_3));

            assertNotNull(environment.getProperty(TEST_KEY_4));
            String key4Value = OBJECT_MAPPER.writeValueAsString(environment.getProperty(TEST_KEY_4));
            assertTrue(key4Value.contains(TEST_VALUE_3));
            assertTrue(key4Value.contains(TEST_VALUE_4_SIGNING_KEY));

            assertNotNull(environment.getProperty(TEST_KEY_5));
            String key5Value = OBJECT_MAPPER.writeValueAsString(
                    environment.getProperty(TEST_KEY_5, UaaConfiguration.OAuth.class));
            assertTrue(key5Value.contains(TEST_VALUE_5_CLIENT_1));
            assertTrue(key5Value.contains(TEST_VALUE_5_CLIENT_1_SECRET));
            assertTrue(key5Value.contains(TEST_VALUE_5_CLIENT_2_SECRET));
            assertTrue(key5Value.contains(TEST_VALUE_5_CLIENT_2));

            // Verify AwsSecretsLoader calls
            assertTrue(myobjectMockedConstruction.constructed().size() > 0);
            AwsSecretsLoader mock = myobjectMockedConstruction.constructed().get(0);
            verify(mock, times(1)).createResourcesFromSecrets(environment);
        }
    }

    @Test
    void testEnvironmentVariablesNotLoadedWithWhitespaceInSecretName() {

        // Set aws secret manager secret names with just empty spaces
        System.setProperty("AWS_SECRET_MANAGER_NAMES", "   ");

        // Assert test keys not present in environment
        assertNull(environment.getProperty(TEST_KEY_1));
        assertNull(environment.getProperty(TEST_KEY_2));
        assertNull(environment.getProperty(TEST_KEY_3));
        assertNull(environment.getProperty(TEST_KEY_4));
        assertNull(environment.getProperty(TEST_KEY_5));

        // Mock AwsSecretsLoader constructor(new AwsSecretsLoader()) call and this mocking is limited to below try block
        try (MockedConstruction<AwsSecretsLoader> myobjectMockedConstruction =
                     Mockito.mockConstruction(AwsSecretsLoader.class, (mock, context) -> {
                         doReturn(null).when(mock).createResourcesFromSecrets(environment);
                     })) {

            addConvertor(environment);
            initializer.initialize(context);

            // Assert test keys not present in environment
            assertNull(environment.getProperty(TEST_KEY_1));
            assertNull(environment.getProperty(TEST_KEY_2));
            assertNull(environment.getProperty(TEST_KEY_3));
            assertNull(environment.getProperty(TEST_KEY_4));
            assertNull(environment.getProperty(TEST_KEY_5));

            // Verify AwsSecretsLoader calls
            assertTrue(myobjectMockedConstruction.constructed().size() > 0);
            AwsSecretsLoader mock = myobjectMockedConstruction.constructed().get(0);
            verify(mock, times(1)).createResourcesFromSecrets(environment);
        }
    }

    @Test
    void testEnvironmentVariablesNotLoadedWithInvalidYamlContent() {

        // Set aws secret manager secret names with just empty spaces
        System.setProperty("AWS_SECRET_MANAGER_NAMES", TEST_SECRET_NAME_1);

        // Assert test keys not present in environment
        assertNull(environment.getProperty(TEST_KEY_1));
        assertNull(environment.getProperty(TEST_KEY_2));
        assertNull(environment.getProperty(TEST_KEY_3));
        assertNull(environment.getProperty(TEST_KEY_4));
        assertNull(environment.getProperty(TEST_KEY_5));

        // Mock AwsSecretsLoader constructor(new AwsSecretsLoader()) call and this mocking is limited to below try block
        try (MockedConstruction<AwsSecretsLoader> myobjectMockedConstruction =
                     Mockito.mockConstruction(AwsSecretsLoader.class, (mock, context) -> {
                         doReturn(resourcesWithInvalidYamlContent()).when(mock).createResourcesFromSecrets(environment);
                     })) {

            addConvertor(environment);
            initializer.initialize(context);

            // Assert test keys not present in environment
            assertNull(environment.getProperty(TEST_KEY_1));
            assertNull(environment.getProperty(TEST_KEY_2));
            assertNull(environment.getProperty(TEST_KEY_3));
            assertNull(environment.getProperty(TEST_KEY_4));
            assertNull(environment.getProperty(TEST_KEY_5));

            // Verify AwsSecretsLoader calls
            assertTrue(myobjectMockedConstruction.constructed().size() > 0);
            AwsSecretsLoader mock = myobjectMockedConstruction.constructed().get(0);
            verify(mock, times(1)).createResourcesFromSecrets(environment);
        }
    }

    private void mockSecretManagerCalls() {
        // Mock aws secret manager calls
        doReturn(awsSecretsManager).when(awsSecretsLoader).awsSecretsManager();
        GetSecretValueResult getSecretValueResult = new GetSecretValueResult();
        getSecretValueResult.setSecretString(vaidYamlString());
        doReturn(getSecretValueResult).when(awsSecretsManager).getSecretValue(any(GetSecretValueRequest.class));
    }

    private void addConvertor(StandardServletEnvironment environment) {
        environment.getConversionService().addConverter(new GenericConverter() {
            @Override
            public Set<ConvertiblePair> getConvertibleTypes() {
                return new HashSet<>(Arrays.asList(
                        new ConvertiblePair(Map.class, String.class),
                        new ConvertiblePair(String.class, Map.class)
                ));
            }

            @Override
            public Object convert(Object source, TypeDescriptor sourceType, TypeDescriptor targetType) {
                return (new Yaml()).dump(source);
            }
        });

        environment.getConversionService().addConverter(new GenericConverter() {
            @Override
            public Set<ConvertiblePair> getConvertibleTypes() {
                return new HashSet<>(Arrays.asList(
                        new ConvertiblePair(UaaConfiguration.OAuth.class, Map.class),
                        new ConvertiblePair(Map.class, UaaConfiguration.OAuth.class)
                ));
            }

            @Override
            public Object convert(Object source, TypeDescriptor sourceType, TypeDescriptor targetType) {
                return OBJECT_MAPPER.convertValue(source, targetType.getType());
            }
        });
    }

    private List<Resource> resources() {
        List<Resource> awsResources = new ArrayList<>();
        Resource resource1 = new ByteArrayResource(vaidYamlString().getBytes(), TEST_SECRET_NAME_1);
        Resource resource2 = new ByteArrayResource("".getBytes(), TEST_SECRET_NAME_2);
        awsResources.add(resource1);
        awsResources.add(resource2);
        return awsResources;
    }

    private List<Resource> resourcesWithInvalidYamlContent() {
        List<Resource> awsResources = new ArrayList<>();
        Resource resource1 = new ByteArrayResource(
                (vaidYamlString() + "\n\nappend invalid yaml format string").getBytes(), TEST_SECRET_NAME_1);
        awsResources.add(resource1);
        return awsResources;
    }
}
