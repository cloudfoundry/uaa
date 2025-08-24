package org.cloudfoundry.identity.uaa.home;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.cloudfoundry.identity.uaa.client.ClientMetadata;
import org.cloudfoundry.identity.uaa.client.JdbcClientMetadataProvisioning;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.Links;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static java.util.Objects.nonNull;
import static org.cloudfoundry.identity.uaa.ratelimiting.RateLimitingFilter.RATE_LIMIT_ERROR_ATTRIBUTE;
import static org.springframework.util.StringUtils.hasText;

@SuppressWarnings("SpringMVCViewInspection")
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
        model.addAllAttributes(new HashMap<>());
    }

    @RequestMapping(value = {"/", "/home"})
    public String home(Model model, Principal principal) {
        IdentityZone identityZone = getIdentityZone();
        IdentityZoneConfiguration config = identityZone.getConfig();
        String homePage =
                config != null && config.getLinks().getHomeRedirect() != null ? config.getLinks().getHomeRedirect() :
                        globalLinks != null && globalLinks.getHomeRedirect() != null ?
                                globalLinks.getHomeRedirect() : null;
        if (homePage != null && !"/".equals(homePage) && !"/home".equals(homePage)) {
            homePage = UaaStringUtils.replaceZoneVariables(homePage, identityZone);
            return "redirect:" + homePage;
        }

        model.addAttribute("principal", principal);

        List<TileData> tiles = new ArrayList<>();
        List<ClientMetadata> clientMetadataList = clientMetadataProvisioning.retrieveAll(identityZone.getId());

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

        return TileData.builder()
                .clientId(clientMetadata.getClientId())
                .appLaunchUrl(clientMetadata.getAppLaunchUrl().toString())
                .appIcon("data:image/png;base64," + clientMetadata.getAppIcon())
                .clientName(clientName)
                .build();
    }

    private boolean shouldShowClient(ClientMetadata clientMetadata) {
        return clientMetadata.isShowOnHomePage() && clientMetadata.getAppLaunchUrl() != null;
    }

    @RequestMapping("/error500")
    public String error500(Model model, HttpServletRequest request, HttpServletResponse response) {
        Throwable genericException = (Throwable) request.getAttribute(RequestDispatcher.ERROR_EXCEPTION);
        logger.error("Internal error", genericException);

        // check for common SAML related exceptions and redirect these to bad_request
        if (nonNull(genericException) &&
                (genericException.getCause() instanceof Saml2Exception samlException)) {
            model.addAttribute("saml_error", samlException.getMessage());
            response.setStatus(400);
            return EXTERNAL_AUTH_ERROR;
        }

        populateBuildAndLinkInfo(model);
        return ERROR;
    }

    @SuppressWarnings("java:S3752")
    @RequestMapping(path = "/error429", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.DELETE, RequestMethod.PUT, RequestMethod.PATCH})
    @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
    @ResponseBody
    public JsonError error429Json(HttpServletRequest request) {
        if (request.getAttribute(RATE_LIMIT_ERROR_ATTRIBUTE) instanceof String rateLimitErrorString) {
            return new JsonError(rateLimitErrorString);
        } else {
            return new JsonError("Too Many Requests");
        }
    }

    @SuppressWarnings("java:S3752")
    @RequestMapping(path = "/error429", produces = MediaType.TEXT_HTML_VALUE, method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.DELETE, RequestMethod.PUT, RequestMethod.PATCH})
    public String error429(Model model, HttpServletRequest request) {
        model.addAttribute(RATE_LIMIT_ERROR_ATTRIBUTE, request.getAttribute(RATE_LIMIT_ERROR_ATTRIBUTE));
        return "error429";
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
        String oauthError = "oauth_error";
        String exception = (String) request.getSession().getAttribute(oauthError);

        if (hasText(exception)) {
            model.addAttribute(oauthError, exception);
            request.getSession().removeAttribute(oauthError);
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

    @SuppressWarnings("deprecation")
    private static IdentityZone getIdentityZone() {
        return IdentityZoneHolder.get();
    }

    @Getter
    @AllArgsConstructor
    @Builder
    private static class TileData {
        private final String clientId;
        private final String appLaunchUrl;
        private final String appIcon;
        private final String clientName;
    }

    public record JsonError(String error) {
    }
}
