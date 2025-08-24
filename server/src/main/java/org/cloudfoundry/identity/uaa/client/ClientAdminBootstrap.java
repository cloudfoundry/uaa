package org.cloudfoundry.identity.uaa.client;

import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration.JWT_CREDS;
import static org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration.JWKS;
import static org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration.JWKS_URI;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_IMPLICIT;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.SystemAuthentication;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.provider.ClientAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class ClientAdminBootstrap implements
        InitializingBean,
        ApplicationListener<ContextRefreshedEvent>,
        ApplicationEventPublisherAware {

    private static final Logger logger = LoggerFactory.getLogger(ClientAdminBootstrap.class);

    private final PasswordEncoder passwordEncoder;
    private final MultitenantClientServices clientRegistrationService;
    private final ClientMetadataProvisioning clientMetadataProvisioning;
    private ApplicationEventPublisher publisher;

    private final Map<String, Map<String, Object>> clients;
    private final Set<String> clientsToDelete;
    private final JdbcTemplate jdbcTemplate;
    private final Set<String> autoApproveClients;
    private final Set<String> allowPublicClients;
    private final boolean defaultOverride;

    /**
     * @param defaultOverride    the default override flag to set. Flag to indicate
     *                           that client details should override existing values
     *                           by default. If true and the override flag is not
     *                           set in the client details input then the details
     *                           will override any existing details with the same id.
     * @param clients            the clients to set
     * @param autoApproveClients A set of client ids that are unconditionally to be
     *                           autoapproved (independent of the settings in the
     *                           client details map). These clients will have
     *                           <code>autoapprove=true</code> when they are inserted
     *                           into the client details store.
     * @param allowPublicClients A set of client ids that are allowed to be used
     *                           without client_secret parameter but with PKCE S256 method
     */
    ClientAdminBootstrap(
            @Qualifier("nonCachingPasswordEncoder") final PasswordEncoder passwordEncoder,
            final MultitenantClientServices clientRegistrationService,
            final ClientMetadataProvisioning clientMetadataProvisioning,
            @Value("${oauth.client.override:true}")final boolean defaultOverride,
            @Value("#{@config['oauth']==null ? null : @config['oauth']['clients']}") final Map<String, Map<String, Object>> clients,
            @Value("#{@applicationProperties.containsKey('oauth.client.autoapprove') ? @config['oauth']['client']['autoapprove'] : 'cf'}") final Collection<String> autoApproveClients,
            @Value("#{@config['delete']==null ? null : @config['delete']['clients']}") final Collection<String> clientsToDelete,
            final JdbcTemplate jdbcTemplate,
            final Set<String> allowPublicClients) {
        this.passwordEncoder = passwordEncoder;
        this.clientRegistrationService = clientRegistrationService;
        this.clientMetadataProvisioning = clientMetadataProvisioning;
        this.defaultOverride = defaultOverride;
        this.clients = ofNullable(clients).orElse(Collections.emptyMap());
        this.autoApproveClients = new HashSet<>(ofNullable(autoApproveClients).orElse(Collections.emptySet()));
        this.clientsToDelete = new HashSet<>(ofNullable(clientsToDelete).orElse(Collections.emptySet()));
        this.jdbcTemplate = jdbcTemplate;
        this.allowPublicClients = new HashSet<>(ofNullable(allowPublicClients).orElse(Collections.emptySet()));
    }

    @Override
    public void afterPropertiesSet() {
        addNewClients();
        updateAutoApproveClients();
        updateAllowedPublicClients();
    }

    /**
     * Explicitly override autoapprove in all clients that were provided in the
     * whitelist.
     */
    private void updateAutoApproveClients() {
        autoApproveClients.removeAll(clientsToDelete);
        for (String clientId : autoApproveClients) {
            try {
                UaaClientDetails base = (UaaClientDetails) clientRegistrationService.loadClientByClientId(clientId, IdentityZone.getUaaZoneId());
                base.addAdditionalInformation(ClientConstants.AUTO_APPROVE, true);
                logger.debug("Adding autoapprove flag to client: {}", clientId);
                clientRegistrationService.updateClientDetails(base, IdentityZone.getUaaZoneId());
            } catch (NoSuchClientException n) {
                logger.debug("Client not found, unable to set autoapprove: {}", clientId);
            }
        }
    }

    private void updateAllowedPublicClients() {
        allowPublicClients.removeAll(clientsToDelete);
        for (String clientId : allowPublicClients) {
            try {
                UaaClientDetails base = (UaaClientDetails) clientRegistrationService.loadClientByClientId(clientId, IdentityZone.getUaaZoneId());
                base.addAdditionalInformation(ClientConstants.ALLOW_PUBLIC, true);
                logger.debug("Adding allowpublic flag to client: {}", clientId);
                clientRegistrationService.updateClientDetails(base, IdentityZone.getUaaZoneId());
            } catch (NoSuchClientException n) {
                logger.debug("Client not found, unable to set allowpublic: {}", clientId);
            }
        }
    }

    private String getRedirectUris(Map<String, Object> map) {
        Set<String> redirectUris = new HashSet<>();
        if (map.get("redirect-uri") != null) {
            redirectUris.add((String) map.get("redirect-uri"));
        }
        if (map.get("signup_redirect_url") != null) {
            redirectUris.add((String) map.get("signup_redirect_url"));
        }
        if (map.get("change_email_redirect_url") != null) {
            redirectUris.add((String) map.get("change_email_redirect_url"));
        }
        return StringUtils.arrayToCommaDelimitedString(redirectUris.toArray(new String[]{}));
    }

    private void addNewClients() {
        Set<Map.Entry<String, Map<String, Object>>> entries = clients.entrySet();
        entries.removeIf(entry -> clientsToDelete.contains(entry.getKey()));
        for (Map.Entry<String, Map<String, Object>> entry : entries) {
            String clientId = entry.getKey();

            Map<String, Object> map = entry.getValue();
            if (map.get("authorized-grant-types") == null) {
                throw new InvalidClientDetailsException("Client must have at least one authorized-grant-type. client ID: " + clientId);
            }
            UaaClientDetails client = new UaaClientDetails(clientId, (String) map.get("resource-ids"),
                    (String) map.get("scope"), (String) map.get("authorized-grant-types"),
                    (String) map.get("authorities"), getRedirectUris(map));

            // support second secret
            String secondSecret = null;
            if (map.get("secret") instanceof List) {
                List<String> secrets = (List<String>) map.get("secret");
                if (!secrets.isEmpty()) {
                    client.setClientSecret(secrets.getFirst() == null ? "" : secrets.getFirst());
                    if (secrets.size() > 1) {
                        secondSecret = secrets.get(1) == null ? "" : secrets.get(1);
                    }
                }
            } else {
                client.setClientSecret((String) map.get("secret"));
            }

            Integer validity = (Integer) map.get("access-token-validity");
            Boolean override = (Boolean) map.get("override");
            if (override == null) {
                override = defaultOverride;
            }
            Map<String, Object> info = new HashMap<>(map);
            if (validity != null) {
                client.setAccessTokenValiditySeconds(validity);
            }
            validity = (Integer) map.get("refresh-token-validity");
            if (validity != null) {
                client.setRefreshTokenValiditySeconds(validity);
            }
            // UAA does not use the resource ids in client registrations
            client.setResourceIds(Collections.singleton("none"));
            if (client.getScope().isEmpty()) {
                client.setScope(Collections.singleton("uaa.none"));
            }
            if (client.getAuthorities().isEmpty()) {
                client.setAuthorities(Collections.singleton(UaaAuthority.UAA_NONE));
            }
            if (client.getAuthorizedGrantTypes().contains(GRANT_TYPE_AUTHORIZATION_CODE)) {
                client.getAuthorizedGrantTypes().add(GRANT_TYPE_REFRESH_TOKEN);
            }
            for (String key : Arrays.asList("resource-ids", "scope", "authorized-grant-types", "authorities",
                    "redirect-uri", "secret", "id", "override", "access-token-validity", "refresh-token-validity",
                    "show-on-homepage", "app-launch-url", "app-icon", JWKS, JWKS_URI, JWT_CREDS)) {
                info.remove(key);
            }

            client.setAdditionalInformation(info);

            ClientJwtConfiguration keyConfig = null;
            if (map.get(JWKS_URI) instanceof String || map.get(JWKS) instanceof String) {
                String jwksUri = (String) map.get(JWKS_URI);
                String jwks = (String) map.get(JWKS);
                keyConfig = ClientJwtConfiguration.parse(jwksUri, jwks);
                writeJwtClientConfiguration(keyConfig, client);
            }

            if (map.get(JWT_CREDS) instanceof String jwtCredential) {
                if (keyConfig == null) {
                    keyConfig = new ClientJwtConfiguration();
                }
                keyConfig.addJwtCredentials(ClientJwtCredential.parse(jwtCredential));
                writeJwtClientConfiguration(keyConfig, client);
            }

            try {
                clientRegistrationService.addClientDetails(client, IdentityZone.getUaaZoneId());
                if (secondSecret != null) {
                    clientRegistrationService.addClientSecret(clientId, secondSecret, IdentityZone.getUaaZoneId());
                }
            } catch (ClientAlreadyExistsException e) {
                if (override) {
                    logger.debug("Overriding client details for {}", clientId);
                    clientRegistrationService.updateClientDetails(client, IdentityZone.getUaaZoneId());
                    updatePasswordsIfChanged(clientId, client.getClientSecret(), secondSecret);
                } else {
                    // ignore it
                    logger.debug(e.getMessage());
                }
            }

            if (map.containsKey("use-bcrypt-prefix") && "true".equals(map.get("use-bcrypt-prefix"))) {
                jdbcTemplate.update("update oauth_client_details set client_secret=concat(?, client_secret) where client_id = ?", "{bcrypt}", clientId);
            }

            for (String s : Arrays.asList(GRANT_TYPE_AUTHORIZATION_CODE, GRANT_TYPE_IMPLICIT)) {
                if (client.getAuthorizedGrantTypes().contains(s) && isMissingRedirectUris(client)) {
                    throw new InvalidClientDetailsException(s + " grant type requires at least one redirect URL. ClientID: " + client.getClientId());
                }
            }

            ClientMetadata clientMetadata = buildClientMetadata(map, clientId);
            clientMetadataProvisioning.update(clientMetadata, IdentityZone.getUaaZoneId());
        }
    }

    private static void writeJwtClientConfiguration(ClientJwtConfiguration keyConfig, UaaClientDetails client) {
        if (keyConfig != null && keyConfig.hasConfiguration()) {
            keyConfig.writeValue(client);
        } else {
            throw new InvalidClientDetailsException("Client jwt configuration invalid syntax. ClientID: " + client.getClientId());
        }
    }

    private boolean isMissingRedirectUris(UaaClientDetails client) {
        return client.getRegisteredRedirectUri() == null || client.getRegisteredRedirectUri().isEmpty();
    }

    private ClientMetadata buildClientMetadata(Map<String, Object> map, String clientId) {
        Boolean showOnHomepage = (Boolean) map.get("show-on-homepage");
        String appLaunchUrl = (String) map.get("app-launch-url");
        String appIcon = (String) map.get("app-icon");
        ClientMetadata clientMetadata = new ClientMetadata();
        clientMetadata.setClientId(clientId);

        clientMetadata.setAppIcon(appIcon);
        clientMetadata.setShowOnHomePage(showOnHomepage != null && showOnHomepage);
        if (StringUtils.hasText(appLaunchUrl)) {
            try {
                clientMetadata.setAppLaunchUrl(new URL(appLaunchUrl));
            } catch (MalformedURLException e) {
                logger.info("Client metadata exception", new ClientMetadataException("Invalid app-launch-url for client " + clientId, e, HttpStatus.INTERNAL_SERVER_ERROR));
            }
        }

        return clientMetadata;
    }

    private void updatePasswordsIfChanged(String clientId, String rawPassword1, String rawPassword2) {
        if (passwordEncoder != null) {
            ClientDetails existing = clientRegistrationService.loadClientByClientId(clientId, IdentityZone.getUaaZoneId());
            String existingSecret = existing.getClientSecret();
            String[] existingPasswordHash = (existingSecret != null ? existingSecret : "").split(" ");
            // check if both passwords are still up to date
            // 1st line: client already has 2 passwords: check if both are still correct
            // 2nd line: client has only 1 pasword: check if password is correct and second password is null
            if ((existingPasswordHash.length > 1 && rawPassword1 != null
                    && passwordEncoder.matches(rawPassword1, existingPasswordHash[0])
                    && rawPassword2 != null && passwordEncoder.matches(rawPassword2, existingPasswordHash[1]))
                    || (rawPassword1 != null && (passwordEncoder.matches(rawPassword1, existingPasswordHash[0]) && rawPassword2 == null))) {
                // no changes to passwords: nothing to do here
                return;
            }
        }
        // at least one password has changed: update
        clientRegistrationService.updateClientSecret(clientId, rawPassword1, IdentityZone.getUaaZoneId());
        if (rawPassword2 != null) {
            clientRegistrationService.addClientSecret(clientId, rawPassword2, IdentityZone.getUaaZoneId());
        }
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent ignored) {
        Authentication auth = SystemAuthentication.SYSTEM_AUTHENTICATION;
        for (String clientId : clientsToDelete) {
            try {
                ClientDetails client = clientRegistrationService.loadClientByClientId(clientId, IdentityZone.getUaaZoneId());
                logger.debug("Deleting client from manifest:{}", clientId);
                EntityDeletedEvent<ClientDetails> delete = new EntityDeletedEvent<>(client, auth, IdentityZoneHolder.getCurrentZoneId());
                publish(delete);
            } catch (NoSuchClientException e) {
                logger.debug("Ignoring delete for non existent client:{}", clientId);
            }
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    public void publish(ApplicationEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }
}
