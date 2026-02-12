package org.cloudfoundry.identity.uaa;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OpenApiConfigurationTest {

    private BuildInfo buildInfo;
    private OpenApiConfiguration openApiConfiguration;

    @BeforeEach
    void setUp() {
        buildInfo = mock(BuildInfo.class);
        when(buildInfo.getVersion()).thenReturn("1.0.0-test");
        when(buildInfo.getUaaUrl()).thenReturn("https://uaa.example.com");
        openApiConfiguration = new OpenApiConfiguration(buildInfo);
    }

    @Test
    void uaaOpenAPIBeanIsCreated() {
        OpenAPI openAPI = openApiConfiguration.uaaOpenAPI();

        assertThat(openAPI).isNotNull();
    }

    @Test
    void openAPIHasCorrectTitle() {
        OpenAPI openAPI = openApiConfiguration.uaaOpenAPI();

        assertThat(openAPI.getInfo().getTitle()).isEqualTo("UAA API Reference");
    }

    @Test
    void openAPIHasDescriptionWithKeyFeatures() {
        OpenAPI openAPI = openApiConfiguration.uaaOpenAPI();

        String description = openAPI.getInfo().getDescription();
        assertThat(description)
                .contains("OAuth2/OpenID Connect")
                .contains("SCIM 2.0")
                .contains("Identity provider integration")
                .contains("Multi-tenancy");
    }

    @Test
    void openAPIVersionComesFromBuildInfo() {
        OpenAPI openAPI = openApiConfiguration.uaaOpenAPI();

        assertThat(openAPI.getInfo().getVersion()).isEqualTo("1.0.0-test");
    }

    @Test
    void openAPIHasCorrectContactInfo() {
        OpenAPI openAPI = openApiConfiguration.uaaOpenAPI();

        assertThat(openAPI.getInfo().getContact().getName()).isEqualTo("Cloud Foundry Foundation");
        assertThat(openAPI.getInfo().getContact().getUrl()).isEqualTo("https://github.com/cloudfoundry/uaa");
    }

    @Test
    void openAPIHasApache2License() {
        OpenAPI openAPI = openApiConfiguration.uaaOpenAPI();

        assertThat(openAPI.getInfo().getLicense().getName()).isEqualTo("Apache 2.0");
        assertThat(openAPI.getInfo().getLicense().getUrl()).isEqualTo("https://www.apache.org/licenses/LICENSE-2.0");
    }

    @Test
    void openAPIServerUrlComesFromBuildInfo() {
        OpenAPI openAPI = openApiConfiguration.uaaOpenAPI();

        assertThat(openAPI.getServers()).hasSize(1);
        assertThat(openAPI.getServers().get(0).getUrl()).isEqualTo("https://uaa.example.com");
        assertThat(openAPI.getServers().get(0).getDescription()).isEqualTo("UAA Server");
    }

    @Test
    void openAPIHasBearerAuthSecurityRequirement() {
        OpenAPI openAPI = openApiConfiguration.uaaOpenAPI();

        assertThat(openAPI.getSecurity()).hasSize(1);
        assertThat(openAPI.getSecurity().get(0).get("bearerAuth")).isNotNull();
    }

    @Test
    void openAPIHasBearerAuthSecurityScheme() {
        OpenAPI openAPI = openApiConfiguration.uaaOpenAPI();

        SecurityScheme securityScheme = openAPI.getComponents().getSecuritySchemes().get("bearerAuth");
        assertThat(securityScheme).isNotNull();
        assertThat(securityScheme.getType()).isEqualTo(SecurityScheme.Type.HTTP);
        assertThat(securityScheme.getScheme()).isEqualTo("bearer");
        assertThat(securityScheme.getBearerFormat()).isEqualTo("JWT");
    }

    @Test
    void securitySchemeDescriptionDocumentsRequiredScopes() {
        OpenAPI openAPI = openApiConfiguration.uaaOpenAPI();

        String description = openAPI.getComponents().getSecuritySchemes().get("bearerAuth").getDescription();
        assertThat(description)
                .contains("uaa.admin")
                .contains("scim.read")
                .contains("scim.write")
                .contains("clients.read")
                .contains("clients.write")
                .contains("zones.read")
                .contains("zones.write")
                .contains("idps.read")
                .contains("idps.write");
    }
}
