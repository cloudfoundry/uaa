package org.cloudfoundry.identity.uaa;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springdoc.core.models.GroupedOpenApi;
import org.springdoc.core.properties.SpringDocConfigProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI 3.0 configuration for UAA SCIM API documentation.
 * 
 * This configuration provides interactive API documentation for UAA SCIM endpoints,
 * specifically focused on admin role management capabilities.
 */
@Configuration
public class OpenApiConfiguration {

    @Bean
    public OpenAPI uaaOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("UAA SCIM 2.0 API")
                        .description("""
                                UAA SCIM 2.0 API endpoints for managing admin roles and user groups.
                                
                                This API provides endpoints for:
                                - Creating and managing groups (admin scopes)
                                - Adding/removing users from groups (assigning admin roles)
                                - Querying users and groups
                                
                                Based on SCIM 2.0 specification and UAA implementation.
                                """)
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("UAA Team")
                                .url("https://github.com/cloudfoundry/uaa"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0")))
                .servers(List.of(
                        new Server()
                                .url("http://localhost:8080/uaa")
                                .description("Local Development"),
                        new Server()
                                .url("https://uaa.example.com")
                                .description("UAA Server")
                ))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("""
                                        OAuth2 Bearer token with required scopes:
                                        - scim.read: Read access to users and groups
                                        - scim.write: Full access to create/update users and groups
                                        - groups.update: Update group memberships
                                        """)));
    }

    @Bean
    public GroupedOpenApi scimApi() {
        return GroupedOpenApi.builder()
                .group("scim")
                .pathsToMatch("/Groups/**", "/Users/**")
                .packagesToScan("org.cloudfoundry.identity.uaa.scim.endpoints")
                .build();
    }

    @Bean
    public SpringDocConfigProperties springDocConfigProperties() {
        SpringDocConfigProperties properties = new SpringDocConfigProperties();
        // Enable YAML format
        properties.setWriterWithDefaultPrettyPrinter(true);
        return properties;
    }
}
