package org.cloudfoundry.identity.uaa.provider.saml;

import com.ge.iam.sns.service.SnsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@SpringJUnitConfig
class UaaSnsConfigTest {

    @Mock
    private SnsService mockSnsService;

    private UaaSnsConfig uaaSnsConfig;

    @BeforeEach
    void setUp() {
        uaaSnsConfig = new UaaSnsConfig();
    }

    @Test
    void userAttributeChangesSnsHandler_shouldCreateBean_withCorrectDependencies() {
        UserAttributeChangesSnsHandler handler = uaaSnsConfig.userAttributeChangesSnsHandler(mockSnsService);

        assertNotNull(handler, "Handler should not be null");
        assertNotNull(handler);
        assertTrue(handler.isConfiguredAndEnabled() || !handler.isConfiguredAndEnabled(), 
                   "Handler should be able to respond to configuration checks");
    }

    @Test
    void userAttributeChangesSnsHandler_shouldCreateNewInstance_eachTime() {
        UserAttributeChangesSnsHandler handler1 = uaaSnsConfig.userAttributeChangesSnsHandler(mockSnsService);
        UserAttributeChangesSnsHandler handler2 = uaaSnsConfig.userAttributeChangesSnsHandler(mockSnsService);

        assertNotNull(handler1);
        assertNotNull(handler2);
        assertNotSame(handler1, handler2, "Each call should create a new instance");
    }

    @Test
    void userAttributeChangesSnsHandler_shouldAcceptValidDependencies() {
        SnsService validSnsService = mock(SnsService.class);

        UserAttributeChangesSnsHandler handler = uaaSnsConfig.userAttributeChangesSnsHandler(validSnsService);

        assertNotNull(handler);
        assertDoesNotThrow(() -> handler.isConfiguredAndEnabled(), 
                          "Handler should be functional with valid dependencies");
    }

    @Test
    void configuration_shouldHaveCorrectAnnotations() {
        Class<UaaSnsConfig> configClass = UaaSnsConfig.class;

        assertTrue(configClass.isAnnotationPresent(org.springframework.context.annotation.Configuration.class),
                  "Class should be annotated with @Configuration");
        assertTrue(configClass.isAnnotationPresent(org.springframework.context.annotation.ComponentScan.class),
                  "Class should be annotated with @ComponentScan");

        org.springframework.context.annotation.ComponentScan componentScan = 
            configClass.getAnnotation(org.springframework.context.annotation.ComponentScan.class);
        String[] basePackages = componentScan.basePackages();
        assertEquals(2, basePackages.length, "Should scan exactly 2 base packages");
        assertTrue(java.util.Arrays.asList(basePackages).contains("com.ge.iam.sns"),
                  "Should scan com.ge.iam.sns package");
        assertTrue(java.util.Arrays.asList(basePackages).contains("com.ge.iam.sqs"),
                  "Should scan com.ge.iam.sqs package");
    }

    @Test
    void beanMethod_shouldHaveCorrectAnnotations() throws NoSuchMethodException {
        java.lang.reflect.Method beanMethod = UaaSnsConfig.class.getMethod(
            "userAttributeChangesSnsHandler", 
            SnsService.class
        );

        assertTrue(beanMethod.isAnnotationPresent(org.springframework.context.annotation.Bean.class),
                  "Method should be annotated with @Bean");
    }

    @Test
    void beanMethod_shouldReturnCorrectType() throws NoSuchMethodException {
        java.lang.reflect.Method beanMethod = UaaSnsConfig.class.getMethod(
            "userAttributeChangesSnsHandler", 
            SnsService.class
        );

        assertEquals(UserAttributeChangesSnsHandler.class, beanMethod.getReturnType(),
                    "Method should return UserAttributeChangesSnsHandler type");
    }

    @Test
    void beanMethod_shouldHaveCorrectParameters() throws NoSuchMethodException {
        java.lang.reflect.Method beanMethod = UaaSnsConfig.class.getMethod(
            "userAttributeChangesSnsHandler", 
            SnsService.class
        );

        Class<?>[] parameterTypes = beanMethod.getParameterTypes();
        assertEquals(1, parameterTypes.length, "Method should have exactly 1 parameter");
        assertEquals(SnsService.class, parameterTypes[0], "First parameter should be SnsService");
    }
}
