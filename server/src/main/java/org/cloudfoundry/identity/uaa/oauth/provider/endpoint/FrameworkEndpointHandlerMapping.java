package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.condition.NameValueExpression;
import org.springframework.web.servlet.mvc.condition.ParamsRequestCondition;
import org.springframework.web.servlet.mvc.condition.PathPatternsRequestCondition;
import org.springframework.web.servlet.mvc.condition.RequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.view.UrlBasedViewResolver;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class FrameworkEndpointHandlerMapping extends RequestMappingHandlerMapping {

    private static final String REDIRECT = UrlBasedViewResolver.REDIRECT_URL_PREFIX;

    private static final String FORWARD = UrlBasedViewResolver.FORWARD_URL_PREFIX;

    private Map<String, String> mappings = new HashMap<>();

    private String approvalParameter = OAuth2Utils.USER_OAUTH_APPROVAL;

    private final Set<String> paths = new HashSet<>();

    private String prefix;

    /**
     * @param prefix the prefix to set
     */
    public void setPrefix(String prefix) {
        if (!StringUtils.hasText(prefix)) {
            prefix = "";
        } else {
            while (prefix.endsWith("/")) {
                prefix = prefix.substring(0, prefix.lastIndexOf("/"));
            }
        }
        this.prefix = prefix;
    }

    /**
     * Custom mappings for framework endpoint paths. The keys in the map are the default framework endpoint path, e.g.
     * "/oauth/authorize", and the values are the desired runtime paths.
     *
     * @param patternMap the mappings to set
     */
    public void setMappings(Map<String, String> patternMap) {
        this.mappings = new HashMap<>(patternMap);
        for (Iterator<String> iterator = mappings.keySet().iterator(); iterator.hasNext(); ) {
            String key = iterator.next();
            String result = mappings.get(key);
            if (result.startsWith(FORWARD)) {
                result = result.substring(FORWARD.length());
            }
            if (result.startsWith(REDIRECT)) {
                result = result.substring(REDIRECT.length());
            }
            mappings.put(key, result);
        }
    }

    /**
     * @return the mapping from default endpoint paths to custom ones (or the default if no customization is known)
     */
    public String getServletPath(String defaultPath) {
        return (prefix == null ? "" : prefix) + getPath(defaultPath);
    }

    /**
     * @return the mapping from default endpoint paths to custom ones (or the default if no customization is known)
     */
    public String getPath(String defaultPath) {
        String result = defaultPath;
        if (mappings.containsKey(defaultPath)) {
            result = mappings.get(defaultPath);
        }
        return result;
    }

    public Set<String> getPaths() {
        return paths;
    }

    /**
     * The name of the request parameter that distinguishes a call to approve an authorization. Default is
     * {@link OAuth2Utils#USER_OAUTH_APPROVAL}.
     *
     * @param approvalParameter the approvalParameter to set
     */
    public void setApprovalParameter(String approvalParameter) {
        this.approvalParameter = approvalParameter;
    }

    public FrameworkEndpointHandlerMapping() {
        // Make sure user-supplied mappings take precedence by default (except the resource mapping)
        setOrder(Ordered.LOWEST_PRECEDENCE - 2);
    }

    /**
     * Detects &#64;FrameworkEndpoint annotations in handler beans.
     *
     * @see RequestMappingHandlerMapping#isHandler(Class)
     */
    @Override
    protected boolean isHandler(Class<?> beanType) {
        return AnnotationUtils.findAnnotation(beanType, FrameworkEndpoint.class) != null;
    }

    @Override
    protected RequestMappingInfo getMappingForMethod(Method method, Class<?> handlerType) {
        RequestMappingInfo defaultMapping = super.getMappingForMethod(method, handlerType);
        if (defaultMapping == null) {
            return null;
        }

        Set<String> patterns = new LinkedHashSet<>();

        PathPatternsRequestCondition pathPatternsCondition = defaultMapping.getPathPatternsCondition();
        if (pathPatternsCondition != null) {
            for (String pattern : pathPatternsCondition.getPatternValues()) {
                patterns.add(getPath(pattern));
                paths.add(pattern);
            }
        }

        ParamsRequestCondition paramsCondition = defaultMapping.getParamsCondition();
        if (!approvalParameter.equals(OAuth2Utils.USER_OAUTH_APPROVAL) && patterns.contains("/oauth/authorize")) {
            Set<NameValueExpression<String>> expressions = paramsCondition.getExpressions();
            String[] modifiedParams = expressions.stream()
                    .map(expr -> OAuth2Utils.USER_OAUTH_APPROVAL.equals(expr.toString()) ? approvalParameter : expr.toString())
                    .toArray(String[]::new);
            paramsCondition = new ParamsRequestCondition(modifiedParams);
        }

        RequestMappingInfo.Builder builder = RequestMappingInfo
                .paths(patterns.toArray(String[]::new))
                .methods(defaultMapping.getMethodsCondition().getMethods().toArray(new RequestMethod[0]))
                .params(paramsCondition.getExpressions().stream().map(NameValueExpression::toString).toArray(String[]::new))
                .headers(defaultMapping.getHeadersCondition().getExpressions().stream().map(NameValueExpression::toString).toArray(String[]::new))
                .consumes(defaultMapping.getConsumesCondition().getConsumableMediaTypes().stream().map(MediaType::toString).toArray(String[]::new))
                .produces(defaultMapping.getProducesCondition().getProducibleMediaTypes().stream().map(MediaType::toString).toArray(String[]::new));

        RequestCondition<?> customCondition = defaultMapping.getCustomCondition();
        if (customCondition != null) {
            builder.customCondition(customCondition);
        }

        return builder.build();
    }
}
