package org.cloudfoundry.identity.uaa;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.cloudfoundry.identity.uaa.home.BuildInfo;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI 3.0 configuration for UAA API documentation.
 * 
 * This configuration provides interactive API documentation for all UAA endpoints,
 * including users, groups, clients, identity zones, and identity providers.
 */
@Configuration
public class OpenApiConfiguration {

    private final BuildInfo buildInfo;

    public OpenApiConfiguration(BuildInfo buildInfo) {
        this.buildInfo = buildInfo;
    }

    @Bean
    public OpenAPI uaaOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("UAA API Reference")
                        .description("""
                                UAA (User Account and Authentication) is an OAuth2/OpenID Connect server 
                                for centralized identity management. This API reference provides endpoints 
                                for managing users, groups, and client applications.
                            
                                Key Features:
                                - OAuth2 & OpenID Connect authentication
                                - SCIM 2.0 user and group management
                                - Identity provider integration (SAML, LDAP, OIDC)
                                - Multi-tenancy via identity zones
                                - Client application management                                
                                """)
                        .version(buildInfo.getVersion())
                        .contact(new Contact()
                                .name("Cloud Foundry Foundation")
                                .url("https://github.com/cloudfoundry/uaa"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0")))
                .servers(List.of(
                        new Server()
                                .url(buildInfo.getUaaUrl())
                                .description("UAA Server")
                ))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("""
                                        OAuth2 Bearer token (JWT format).
                                    
                                        Required scopes vary by endpoint:
                                        - OAuth/Token: uaa.admin, clients.admin
                                        - Users/Groups: scim.read, scim.write, groups.update
                                        - Clients: clients.read, clients.write, clients.admin
                                        - Identity Zones: zones.read, zones.write, uaa.admin
                                        - Identity Providers: idps.read, idps.write
                                    
                                        Obtain tokens via /oauth/token endpoint.
                                        """)));
    }
}