package org.cloudfoundry.identity.uaa.impl.config;

import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
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
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AwsSecretsLoaderTest {

    private AwsSecretsLoader awsSecretsLoader;
    private StandardServletEnvironment environment;
    private AWSSecretsManager awsSecretsManager;
    private YamlServletProfileInitializer initializer;
    private ConfigurableWebApplicationContext context;

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
        ServletContext servletContext = mock(ServletContext.class);

        doReturn(servletContext).when(context).getServletContext();
        doReturn(environment).when(context).getEnvironment();
        doReturn("/context").when(servletContext).getContextPath();
    }

    @AfterEach
    void cleanup() {
        // Clear aws secret manager secret names
        System.clearProperty("AWS_SECRET_MANAGER_NAMES");
    }

    private static String validYamlString() {
        return TEST_KEY_1 + ": " + TEST_VALUE_1 + "\n" +
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
     }

    private static String validJsonString() throws JsonProcessingException {
        String yamlString = validYamlString();
        Yaml yaml = new Yaml();
        Map<String, Object> map = yaml.load(yamlString);
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.convertValue(map, JsonNode.class);
        return objectMapper.writeValueAsString(jsonNode);
    }

    @Test
    void testCreateResourcesFromSingleSecretName() {
        System.setProperty("AWS_SECRET_MANAGER_NAMES", TEST_SECRET_NAME_1);
        mockSecretManagerCalls();
        List<Resource> resources = awsSecretsLoader.createResourcesFromSecrets(environment);
        assertNotNull(resources);
        assertEquals(1, resources.size());
        assertTrue(resources.get(0).getDescription().contains(TEST_SECRET_NAME_1));
        verify(awsSecretsLoader, times(1)).awsSecretsManager();
    }

    @Test
    void testCreateResourcesFromMultipleSecretName() {
        System.setProperty("AWS_SECRET_MANAGER_NAMES", TEST_SECRET_NAME_1 + ";" + TEST_SECRET_NAME_2);
        mockSecretManagerCalls();
        List<Resource> resources = awsSecretsLoader.createResourcesFromSecrets(environment);
        assertNotNull(resources);
        assertEquals(2, resources.size());
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

    @ParameterizedTest(name = "testEnvironmentVariablesLoadedFromSecretNameWithValidContent(): {index}")
    @MethodSource("getValidContent")
    void testEnvironmentVariablesLoadedFromSecretNameWithValidContent(List<Resource> resources) throws JsonProcessingException {

        // Set aws secret manager secret names
        System.setProperty("AWS_SECRET_MANAGER_NAMES", TEST_SECRET_NAME_1 + ";" + TEST_SECRET_NAME_2);

        // Assert test keys not present in environment
        assertNull(environment.getProperty(TEST_KEY_1));
        assertNull(environment.getProperty(TEST_KEY_2));
        assertNull(environment.getProperty(TEST_KEY_3));
        assertNull(environment.getProperty(TEST_KEY_4));
        assertNull(environment.getProperty(TEST_KEY_5));

        // Mock AwsSecretsLoader constructor(new AwsSecretsLoader()) call and this mocking is limited to below try block
        try (MockedConstruction<AwsSecretsLoader> mockedConstruction =
                     Mockito.mockConstruction(AwsSecretsLoader.class, (mock, context) ->
                             doReturn(resources).when(mock).createResourcesFromSecrets(environment))) {

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
            assertTrue(mockedConstruction.constructed().size() > 0);
            AwsSecretsLoader mock = mockedConstruction.constructed().get(0);
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
        try (MockedConstruction<AwsSecretsLoader> mockedConstruction =
                     Mockito.mockConstruction(AwsSecretsLoader.class, (mock, context)
                             -> doReturn(null).when(mock).createResourcesFromSecrets(environment))) {

            addConvertor(environment);
            initializer.initialize(context);

            // Assert test keys not present in environment
            assertNull(environment.getProperty(TEST_KEY_1));
            assertNull(environment.getProperty(TEST_KEY_2));
            assertNull(environment.getProperty(TEST_KEY_3));
            assertNull(environment.getProperty(TEST_KEY_4));
            assertNull(environment.getProperty(TEST_KEY_5));

            // Verify AwsSecretsLoader calls
            assertTrue(mockedConstruction.constructed().size() > 0);
            AwsSecretsLoader mock = mockedConstruction.constructed().get(0);
            verify(mock, times(1)).createResourcesFromSecrets(environment);
        }
    }

    @ParameterizedTest(name = "testEnvironmentVariablesNotLoadedWithInvalidContent(): {index}")
    @MethodSource("getInvalidContent")
    void testEnvironmentVariablesNotLoadedWithInvalidContent(List<Resource> resources) {

        // Set aws secret manager secret names
        System.setProperty("AWS_SECRET_MANAGER_NAMES", TEST_SECRET_NAME_1);

        // Assert test keys not present in environment
        assertNull(environment.getProperty(TEST_KEY_1));
        assertNull(environment.getProperty(TEST_KEY_2));
        assertNull(environment.getProperty(TEST_KEY_3));
        assertNull(environment.getProperty(TEST_KEY_4));
        assertNull(environment.getProperty(TEST_KEY_5));

        // Mock AwsSecretsLoader constructor(new AwsSecretsLoader()) call and this mocking is limited to below try block
        try (MockedConstruction<AwsSecretsLoader> mockedConstruction =
                     Mockito.mockConstruction(AwsSecretsLoader.class, (mock, context) ->
                             doReturn(resources).when(mock).createResourcesFromSecrets(environment))) {

            addConvertor(environment);
            initializer.initialize(context);

            // Assert test keys not present in environment
            assertNull(environment.getProperty(TEST_KEY_1));
            assertNull(environment.getProperty(TEST_KEY_2));
            assertNull(environment.getProperty(TEST_KEY_3));
            assertNull(environment.getProperty(TEST_KEY_4));
            assertNull(environment.getProperty(TEST_KEY_5));

            // Verify AwsSecretsLoader calls
            assertTrue(mockedConstruction.constructed().size() > 0);
            AwsSecretsLoader mock = mockedConstruction.constructed().get(0);
            verify(mock, times(1)).createResourcesFromSecrets(environment);
        }
    }

    private void mockSecretManagerCalls() {
        // Mock aws secret manager calls
        doReturn(awsSecretsManager).when(awsSecretsLoader).awsSecretsManager();
        GetSecretValueResult getSecretValueResult = new GetSecretValueResult();
        getSecretValueResult.setSecretString(validYamlString());
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

    private static List<Resource> resourcesWithValidYamlContent() {
        List<Resource> awsResources = new ArrayList<>();
        Resource resource1 = new ByteArrayResource(validYamlString().getBytes(), TEST_SECRET_NAME_1);
        Resource resource2 = new ByteArrayResource("".getBytes(), TEST_SECRET_NAME_2);
        awsResources.add(resource1);
        awsResources.add(resource2);
        return awsResources;
    }

    private static List<Resource> resourcesWithInvalidYamlContent() {
        List<Resource> awsResources = new ArrayList<>();
        Resource resource1 = new ByteArrayResource(
                (validYamlString() + "\n\nappend invalid yaml format string").getBytes(), TEST_SECRET_NAME_1);
        awsResources.add(resource1);
        return awsResources;
    }

    private static List<Resource> resourcesWithValidJsonContent() throws JsonProcessingException {
        List<Resource> awsResources = new ArrayList<>();
        Resource resource1 = new ByteArrayResource(validJsonString().getBytes(), TEST_SECRET_NAME_1);
        Resource resource2 = new ByteArrayResource("{}".getBytes(), TEST_SECRET_NAME_2);
        awsResources.add(resource1);
        awsResources.add(resource2);
        return awsResources;
    }

    private static List<Resource> resourcesWithInvalidJsonContent() throws JsonProcessingException {
        List<Resource> awsResources = new ArrayList<>();
        Resource resource1 = new ByteArrayResource(
                (validJsonString() + "\n\nappend invalid json format string").getBytes(), TEST_SECRET_NAME_1);
        awsResources.add(resource1);
        return awsResources;
    }

    private static Stream<List<Resource>> getValidContent() throws JsonProcessingException {
        return Stream.of(resourcesWithValidYamlContent(), resourcesWithValidJsonContent());
    }

    private static Stream<List<Resource>> getInvalidContent() throws JsonProcessingException {
        return Stream.of(resourcesWithInvalidYamlContent(), resourcesWithInvalidJsonContent());
    }
}
