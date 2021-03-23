package org.cloudfoundry.identity.uaa.client;

import static java.util.Optional.ofNullable;
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
import java.util.Map;
import java.util.Set;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.SystemAuthentication;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.StringUtils;

public class ClientAdminBootstrap implements
        InitializingBean,
        ApplicationListener<ContextRefreshedEvent>,
        ApplicationEventPublisherAware {

    private static Logger logger = LoggerFactory.getLogger(ClientAdminBootstrap.class);

    private final PasswordEncoder passwordEncoder;
    private final MultitenantClientServices clientRegistrationService;
    private final ClientMetadataProvisioning clientMetadataProvisioning;
    private ApplicationEventPublisher publisher;

    private final Map<String, Map<String, Object>> clients;
    private final Set<String> clientsToDelete;
    private final JdbcTemplate jdbcTemplate;
    private final Set<String> autoApproveClients;
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
     */
    ClientAdminBootstrap(
            final PasswordEncoder passwordEncoder,
            final MultitenantClientServices clientRegistrationService,
            final ClientMetadataProvisioning clientMetadataProvisioning,
            final boolean defaultOverride,
            final Map<String, Map<String, Object>> clients,
            final Collection<String> autoApproveClients,
            final Collection<String> clientsToDelete,
            final JdbcTemplate jdbcTemplate) {
        this.passwordEncoder = passwordEncoder;
        this.clientRegistrationService = clientRegistrationService;
        this.clientMetadataProvisioning = clientMetadataProvisioning;
        this.defaultOverride = defaultOverride;
        this.clients = ofNullable(clients).orElse(Collections.emptyMap());
        this.autoApproveClients = new HashSet<>(ofNullable(autoApproveClients).orElse(Collections.emptySet()));
        this.clientsToDelete = new HashSet<>(ofNullable(clientsToDelete).orElse(Collections.emptySet()));
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void afterPropertiesSet() {
        addNewClients();
        updateAutoApproveClients();
    }

    /**
     * Explicitly override autoapprove in all clients that were provided in the
     * whitelist.
     */
    private void updateAutoApproveClients() {
        autoApproveClients.removeAll(clientsToDelete);
        for (String clientId : autoApproveClients) {
            try {
                BaseClientDetails base = (BaseClientDetails) clientRegistrationService.loadClientByClientId(clientId, IdentityZone.getUaaZoneId());
                base.addAdditionalInformation(ClientConstants.AUTO_APPROVE, true);
                logger.debug("Adding autoapprove flag to client: " + clientId);
                clientRegistrationService.updateClientDetails(base, IdentityZone.getUaaZoneId());
            } catch (NoSuchClientException n) {
                logger.debug("Client not found, unable to set autoapprove: " + clientId);
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
            BaseClientDetails client = new BaseClientDetails(clientId, (String) map.get("resource-ids"),
                    (String) map.get("scope"), (String) map.get("authorized-grant-types"),
                    (String) map.get("authorities"), getRedirectUris(map));

            client.setClientSecret(map.get("secret") == null ? "" : (String) map.get("secret"));

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
                    "redirect-uri", "secret", "id", "override", "access-token-validity",
                    "refresh-token-validity", "show-on-homepage", "app-launch-url", "app-icon")) {
                info.remove(key);
            }

            client.setAdditionalInformation(info);
            try {
                clientRegistrationService.addClientDetails(client, IdentityZone.getUaaZoneId());
            } catch (ClientAlreadyExistsException e) {
                if (override) {
                    logger.debug("Overriding client details for " + clientId);
                    clientRegistrationService.updateClientDetails(client, IdentityZone.getUaaZoneId());
                    if (didPasswordChange(clientId, client.getClientSecret())) {
                        clientRegistrationService.updateClientSecret(clientId, client.getClientSecret(), IdentityZone.getUaaZoneId());
                    }
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

    private boolean isMissingRedirectUris(BaseClientDetails client) {
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

    private boolean didPasswordChange(String clientId, String rawPassword) {
        if (passwordEncoder != null) {
            ClientDetails existing = clientRegistrationService.loadClientByClientId(clientId, IdentityZone.getUaaZoneId());
            String existingPasswordHash = existing.getClientSecret();
            return !passwordEncoder.matches(rawPassword, existingPasswordHash);
        } else {
            return true;
        }
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent ignored) {
        Authentication auth = SystemAuthentication.SYSTEM_AUTHENTICATION;
        for (String clientId : clientsToDelete) {
            try {
                ClientDetails client = clientRegistrationService.loadClientByClientId(clientId, IdentityZone.getUaaZoneId());
                logger.debug("Deleting client from manifest:" + clientId);
                EntityDeletedEvent<ClientDetails> delete = new EntityDeletedEvent<>(client, auth, IdentityZoneHolder.getCurrentZoneId());
                publish(delete);
            } catch (NoSuchClientException e) {
                logger.debug("Ignoring delete for non existent client:" + clientId);
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
