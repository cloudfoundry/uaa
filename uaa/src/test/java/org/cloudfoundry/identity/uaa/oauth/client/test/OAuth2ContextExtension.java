package org.cloudfoundry.identity.uaa.oauth.client.test;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.config.RequestConfig.Builder;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.cloudfoundry.identity.uaa.oauth.client.DefaultOAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2AccessDeniedException;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.junit.internal.runners.statements.RunBefores;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;
import org.junit.runners.model.TestClass;
import org.springframework.beans.BeanUtils;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.util.ClassUtils;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Moved class OAuth2ContextSetup implementation of from spring-security-oauth2 into UAA
 * <p>
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 * Migration to Junit5 extension.
 * <p>
 * Scope: Test
 * <p>
 * There is a second class in the samples module that is mostly the same. Should refactor Test Utils for reuse.
 */
public final class OAuth2ContextExtension implements BeforeAllCallback, BeforeEachCallback, AfterEachCallback {

    private static final Log logger = LogFactory.getLog(OAuth2ContextExtension.class);

    private OAuth2ProtectedResourceDetails resource;

    private OAuth2RestTemplate client;

    private Map<String, String> parameters = new LinkedHashMap<>();

    private final RestTemplateHolder clientHolder;

    private final TestAccounts testAccounts;

    private final TestAccountExtension testAccountExtension;

    private OAuth2AccessToken accessToken;

    private boolean initializeAccessToken = true;

    private RestOperations savedClient;

    private AccessTokenProvider accessTokenProvider;

    private final Environment environment;

    /**
     * Create a new client that can inject an Environment into its protected resource
     * details.
     *
     * @param clientHolder receives an OAuth2RestTemplate with the authenticated client
     *                     for the duration of a test
     * @param environment  a Spring Environment that can be used to initialize the client
     * @return a rule that wraps test methods in an OAuth2 context
     */
    public static OAuth2ContextExtension withEnvironment(RestTemplateHolder clientHolder,
                                                         Environment environment) {
        return new OAuth2ContextExtension(clientHolder, null, environment);
    }

    /**
     * Create a new client that can inject a {@link TestAccounts} instance into its
     * protected resource details.
     *
     * @param clientHolder         receives an OAuth2RestTemplate with the authenticated client
     *                             for the duration of a test
     * @param testAccountExtension a test account generator that can be used to initialize the
     *                             client
     * @return a rule that wraps test methods in an OAuth2 context
     */
    public static OAuth2ContextExtension withTestAccounts(RestTemplateHolder clientHolder,
                                                          TestAccountExtension testAccountExtension) {
        return new OAuth2ContextExtension(clientHolder, testAccountExtension, null);
    }

    /**
     * Create a new client that knows how to create its protected resource with no
     * externalization help. Typically, it will use resource details which accept an
     * instance of the current test case (downcasting it from Object). For example
     *
     * <pre>
     * static class MyClientDetailsResource extends ClientCredentialsProtectedResourceDetails {
     * 	public MyClientDetailsResource(Object target) {
     *             MyIntegrationTests test = (MyIntegrationTests) target;
     *             ... do stuff with test instance to initialize the client credentials
     *         }
     * }
     * </pre>
     *
     * @param clientHolder receives an OAuth2RestTemplate with the authenticated client
     *                     for the duration of a test
     * @return a rule that wraps test methods in an OAuth2 context
     */
    public static OAuth2ContextExtension standard(RestTemplateHolder clientHolder) {
        return new OAuth2ContextExtension(clientHolder, null, null);
    }

    private OAuth2ContextExtension(RestTemplateHolder clientHolder,
                                   TestAccountExtension testAccountExtension, Environment environment) {
        this.clientHolder = clientHolder;
        this.testAccountExtension = testAccountExtension;
        this.testAccounts = testAccountExtension.getTestAccounts();
        this.environment = environment;
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        logger.warn("Applying OAuth2 context for: " + context.getRequiredTestClass());
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        logger.warn("Applying OAuth2 context for: " + context.getRequiredTestClass());
        resetExtension();

        initializeIfNecessary(context);
        if (resource != null) {
            logger.info("Starting OAuth2 context for: " + resource);
            AccessTokenRequest request = new DefaultAccessTokenRequest();
            request.setAll(parameters);
            client = createRestTemplate(resource, request);
            if (initializeAccessToken) {
                this.accessToken = null;
                this.accessToken = getAccessToken();
            }
            savedClient = clientHolder.getRestTemplate();
            clientHolder.setRestTemplate(client);
        }
    }

    @Override
    public void afterEach(ExtensionContext context) {
        if (resource != null) {
            logger.info("Ending OAuth2 context for: " + resource);
            if (savedClient != null) {
                clientHolder.setRestTemplate(savedClient);
            }
        }
    }

    private void resetExtension() {
        resource = null;
        accessToken = null;
    }

    private void initializeIfNecessary(ExtensionContext context) {
        if (testAccountExtension != null) {
            testAccountExtension.beforeAll(context);
        }

        final TestClass testClass = new TestClass(context.getRequiredTestClass());
        OAuth2ContextConfiguration contextConfiguration = findOAuthContextConfiguration(context.getRequiredTestMethod(), testClass);
        if (contextConfiguration == null) {
            // Nothing to do
            return;
        }

        initializeAccessToken = contextConfiguration.initialize();
        resource = createResource(context.getRequiredTestInstance(), contextConfiguration);

        final List<FrameworkMethod> befores = testClass.getAnnotatedMethods(BeforeOAuth2Context.class);
        if (!befores.isEmpty()) {
            logger.debug("Running @BeforeOAuth2Context methods");
            for (FrameworkMethod before : befores) {
                RestOperations savedServerClient = clientHolder.getRestTemplate();

                OAuth2ContextConfiguration beforeConfiguration = findOAuthContextConfiguration(before.getMethod(), testClass);
                if (beforeConfiguration != null) {

                    OAuth2ProtectedResourceDetails resource = createResource(context.getRequiredTestInstance(), beforeConfiguration);
                    AccessTokenRequest beforeRequest = new DefaultAccessTokenRequest();
                    beforeRequest.setAll(parameters);
                    OAuth2RestTemplate client = createRestTemplate(resource, beforeRequest);
                    clientHolder.setRestTemplate(client);
                }

                AccessTokenRequest request = new DefaultAccessTokenRequest();
                request.setAll(parameters);
                client = createRestTemplate(this.resource, request);

                List<FrameworkMethod> list = List.of(before);
                try {
                    new RunBefores(new Statement() {
                        public void evaluate() {
                        }
                    }, list, context.getRequiredTestInstance()).evaluate();
                } catch (RuntimeException | AssertionError e) {
                    throw e;
                } catch (Throwable e) {
                    logger.debug("Exception in befores", e);
                } finally {
                    clientHolder.setRestTemplate(savedServerClient);
                }
            }
        }
    }

    public void setAccessTokenProvider(AccessTokenProvider accessTokenProvider) {
        this.accessTokenProvider = accessTokenProvider;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    /**
     * Get the current access token. Should be available inside a test method as long as a
     * resource has been setup with {@link OAuth2ContextConfiguration
     * &#64;OAuth2ContextConfiguration}.
     *
     * @return the current access token initializing it if necessary
     */
    public OAuth2AccessToken getAccessToken() {
        if (resource == null || client == null) {
            return null;
        }
        if (accessToken != null) {
            return accessToken;
        }
        if (accessTokenProvider != null) {
            client.setAccessTokenProvider(accessTokenProvider);
        }
        try {
            return client.getAccessToken();
        } catch (OAuth2AccessDeniedException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException exception) {
                throw exception;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw e;
        }
    }

    /**
     * @return the client template
     */
    public OAuth2RestTemplate getRestTemplate() {
        return client;
    }

    /**
     * @return the current client resource details
     */
    public OAuth2ProtectedResourceDetails getResource() {
        return resource;
    }

    /**
     * @return the current access token request
     */
    public AccessTokenRequest getAccessTokenRequest() {
        return client.getOAuth2ClientContext().getAccessTokenRequest();
    }

    /**
     * @return the current OAuth2 context
     */
    public OAuth2ClientContext getOAuth2ClientContext() {
        return client.getOAuth2ClientContext();
    }

    private OAuth2RestTemplate createRestTemplate(
            OAuth2ProtectedResourceDetails resource, AccessTokenRequest request) {
        OAuth2ClientContext context = new DefaultOAuth2ClientContext(request);
        OAuth2RestTemplate client = new OAuth2RestTemplate(resource, context);
        setupConnectionFactory(client);
        client.setErrorHandler(new DefaultResponseErrorHandler() {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return false;
            }
        });
        if (accessTokenProvider != null) {
            client.setAccessTokenProvider(accessTokenProvider);
        }
        return client;
    }

    private void setupConnectionFactory(OAuth2RestTemplate client) {
        if (Boolean.getBoolean("http.components.enabled")
                && ClassUtils.isPresent("org.apache.http.client.config.RequestConfig",
                null)) {
            client.setRequestFactory(new HttpComponentsClientHttpRequestFactory() {
                @Override
                protected HttpContext createHttpContext(HttpMethod httpMethod, URI uri) {
                    HttpClientContext context = HttpClientContext.create();
                    context.setRequestConfig(getRequestConfig());
                    return context;
                }

                protected RequestConfig getRequestConfig() {
                    Builder builder = RequestConfig.custom()
                            .setCookieSpec(StandardCookieSpec.IGNORE)
                            .setAuthenticationEnabled(false).setRedirectsEnabled(false);
                    return builder.build();
                }
            });
        } else {
            client.setRequestFactory(new SimpleClientHttpRequestFactory() {
                @Override
                protected void prepareConnection(HttpURLConnection connection,
                                                 String httpMethod) throws IOException {
                    super.prepareConnection(connection, httpMethod);
                    connection.setInstanceFollowRedirects(false);
                }
            });
        }
    }

    private OAuth2ProtectedResourceDetails createResource(Object target,
                                                          OAuth2ContextConfiguration contextLoader) {
        Class<? extends OAuth2ProtectedResourceDetails> type = contextLoader.value();
        if (type == OAuth2ProtectedResourceDetails.class) {
            type = contextLoader.resource();
        }
        Constructor<? extends OAuth2ProtectedResourceDetails> constructor = ClassUtils
                .getConstructorIfAvailable(type, TestAccounts.class);
        if (constructor != null && testAccounts != null) {
            return BeanUtils.instantiateClass(constructor, testAccounts);
        }
        constructor = ClassUtils.getConstructorIfAvailable(type, Environment.class);
        if (constructor != null && environment != null) {
            return BeanUtils.instantiateClass(constructor, environment);
        }
        constructor = ClassUtils.getConstructorIfAvailable(type, Object.class);
        if (constructor != null) {
            return BeanUtils.instantiateClass(constructor, target);
        }
        // Fallback to default constructor
        return BeanUtils.instantiate(type);
    }

    private OAuth2ContextConfiguration findOAuthContextConfiguration(Method method, TestClass testClass) {
        OAuth2ContextConfiguration methodConfiguration = method.getAnnotation(OAuth2ContextConfiguration.class);
        if (methodConfiguration != null) {
            return methodConfiguration;
        }
        if (testClass.getJavaClass()
                .isAnnotationPresent(OAuth2ContextConfiguration.class)) {
            return testClass.getJavaClass().getAnnotation(
                    OAuth2ContextConfiguration.class);
        }
        return null;
    }
}
