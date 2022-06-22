package org.cloudfoundry.identity.uaa.home;

import org.cloudfoundry.identity.uaa.client.ClientMetadata;
import org.cloudfoundry.identity.uaa.client.JdbcClientMetadataProvisioning;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.nonNull;
import static org.springframework.util.StringUtils.hasText;

@Controller
public class HomeController {

    private static final String EXTERNAL_AUTH_ERROR = "external_auth_error";
    private static final String ERROR = "error";
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final JdbcClientMetadataProvisioning clientMetadataProvisioning;
    private final Links globalLinks;

    /**
     * @param buildInfo This is required for Thymeleaf templates
     */
    public HomeController(
            final JdbcClientMetadataProvisioning clientMetadataProvisioning,
            @SuppressWarnings("unused") final BuildInfo buildInfo,
            @Qualifier("globalLinks") final Links globalLinks) {
        this.clientMetadataProvisioning = clientMetadataProvisioning;
        this.globalLinks = globalLinks;
    }

    private void populateBuildAndLinkInfo(Model model) {
        Map<String, Object> attributes = new HashMap<>();
        model.addAllAttributes(attributes);
    }

    @RequestMapping(value = {"/", "/home"})
    public String home(Model model, Principal principal) {
        IdentityZoneConfiguration config = IdentityZoneHolder.get().getConfig();
        String homePage =
                config != null && config.getLinks().getHomeRedirect() != null ? config.getLinks().getHomeRedirect() :
                        globalLinks != null && globalLinks.getHomeRedirect() != null ?
                                globalLinks.getHomeRedirect() : null;
        if (homePage != null && !"/".equals(homePage) && !"/home".equals(homePage)) {
            homePage = UaaStringUtils.replaceZoneVariables(homePage, IdentityZoneHolder.get());
            return "redirect:" + homePage;
        }

        model.addAttribute("principal", principal);

        List<TileData> tiles = new ArrayList<>();
        List<ClientMetadata> clientMetadataList = clientMetadataProvisioning.retrieveAll(IdentityZoneHolder.get().getId());

        clientMetadataList.stream()
                .filter(this::shouldShowClient)
                .map(this::tileDataForClient)
                .forEach(tiles::add);

        model.addAttribute("tiles", tiles);

        populateBuildAndLinkInfo(model);

        return "home";
    }

    private TileData tileDataForClient(ClientMetadata clientMetadata) {
        String clientName;

        if (hasText(clientMetadata.getClientName())) {
            clientName = clientMetadata.getClientName();
        } else {
            clientName = clientMetadata.getClientId();
        }

        return new TileData(
                clientMetadata.getClientId(),
                clientMetadata.getAppLaunchUrl().toString(),
                "data:image/png;base64," + clientMetadata.getAppIcon(),
                clientName
        );
    }

    private boolean shouldShowClient(ClientMetadata clientMetadata) {
        return clientMetadata.isShowOnHomePage() && clientMetadata.getAppLaunchUrl() != null;
    }

    @RequestMapping("/error500")
    public String error500(Model model, HttpServletRequest request) {
        logger.error("Internal error", (Throwable) request.getAttribute("javax.servlet.error.exception"));

        populateBuildAndLinkInfo(model);
        return ERROR;
    }

    @RequestMapping({"/error", "/error**"})
    public String errorGeneric(Model model) {
        populateBuildAndLinkInfo(model);
        return ERROR;
    }

    @RequestMapping("/saml_error")
    public String error401(Model model, HttpServletRequest request) {
        AuthenticationException exception = SessionUtils.getAuthenticationException(request.getSession());

        if (nonNull(exception)) {
            model.addAttribute("saml_error", exception.getMessage());
        }
        return EXTERNAL_AUTH_ERROR;
    }

    @RequestMapping("/oauth_error")
    public String error_oauth(Model model, HttpServletRequest request) {
        String OAUTH_ERROR = "oauth_error";
        String exception = (String) request.getSession().getAttribute(OAUTH_ERROR);

        if (hasText(exception)) {
            model.addAttribute(OAUTH_ERROR, exception);
            request.getSession().removeAttribute(OAUTH_ERROR);
        }
        return EXTERNAL_AUTH_ERROR;
    }

    @RequestMapping("/rejected")
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleRequestRejected(Model model,
        @RequestAttribute(RequestDispatcher.ERROR_EXCEPTION) RequestRejectedException ex,
        @RequestAttribute(RequestDispatcher.ERROR_REQUEST_URI) String uri) {

        logger.error("Request with encoded URI [{}] rejected. {}", URLEncoder.encode(uri, StandardCharsets.UTF_8), ex.getMessage());
        model.addAttribute("oauth_error", "The request was rejected because it contained a potentially malicious character.");

        return EXTERNAL_AUTH_ERROR;
    }

    private static class TileData {
        private String appLaunchUrl;
        private String appIcon;
        private String clientId;
        private String clientName;

        private TileData(String clientId, String appLaunchUrl, String appIcon, String clientName) {
            this.appLaunchUrl = appLaunchUrl;
            this.appIcon = appIcon;
            this.clientId = clientId;
            this.clientName = clientName;
        }

        public String getClientId() {
            return clientId;
        }

        public String getAppIcon() {
            return appIcon;
        }

        public String getAppLaunchUrl() {
            return appLaunchUrl;
        }

        public String getClientName() {
            return clientName;
        }
    }
}
