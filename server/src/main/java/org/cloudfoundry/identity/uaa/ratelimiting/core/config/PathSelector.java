package org.cloudfoundry.identity.uaa.ratelimiting.core.config;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.ratelimiting.core.config.exception.RateLimitingConfigException;

import lombok.EqualsAndHashCode;
import lombok.Getter;

@EqualsAndHashCode
@Getter
public final class PathSelector {
    private final PathMatchType type;
    private final String path;

    private PathSelector(PathMatchType type, String path) {
        this.type = type;
        this.path = path;
    }

    @Override
    public String toString() {
        return type + ":" + path;
    }

    public static List<PathSelector> listFrom(String name, List<String> pathSelectors) {
        List<PathSelector> selectors = new ArrayList<>();
        if (pathSelectors != null) {
            for (int i = 0; i < pathSelectors.size(); i++) {
                PathSelector selector = parse(pathSelectors.get(i), i, name);
                if (selector != null) {
                    selectors.add(selector);
                }
            }
        }
        if (selectors.isEmpty()) {
            throw new RateLimitingConfigException( "No pathSelectors from Rate Limiting configuration with name: " + name );
        }
        return selectors;
    }

    // package friendly for testing
    static PathSelector parse(String selectorStr, int offsetIndex, String name) {
        selectorStr = StringUtils.stripToNull(selectorStr);
        if (selectorStr == null) {
            return null;
        }
        String typeStr = selectorStr;
        String path = "";
        int at = typeStr.indexOf(':');
        if (at != -1) {
            typeStr = at == 0 ? "" : selectorStr.substring(0, at).trim();
            path = selectorStr.substring(at + 1).trim();
        }
        PathMatchType type = pathMatchType(typeStr);
        if (type == null) {
            error(offsetIndex, name, "type", typeStr, selectorStr, "must match one of: " + PathMatchType.options());
        }
        String error = type.pathUnacceptable(path);
        if (error != null) {
            error(offsetIndex, name, "path", path, selectorStr, error);
        }
        return new PathSelector( type, path );
    }

    private static void error(int offsetIndex, String name, String whatField, String fieldValue, String selectorStr, String suffix) {
        throw new RateLimitingConfigException( name + "'s PathSelector[" + offsetIndex + "] '" + whatField + "'" +
                " ('" + fieldValue + "' in '" + selectorStr + "') - " + suffix );
    }

    // package friendly for testing
    static PathMatchType pathMatchType(String typeStr) {
        if (!typeStr.isEmpty()) {
            for (PathMatchType pmType : PathMatchType.values()) {
                if (pmType.name().equalsIgnoreCase(typeStr)) {
                    return pmType;
                }
            }
        }
        return null; // indicates not valid
    }
}
