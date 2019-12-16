/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.impl.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;
import org.yaml.snakeyaml.Yaml;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.prettyPrintYaml;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.redactValues;

public class YamlProcessor {

    public interface MatchCallback {
        void process(Properties properties, Map<String, Object> map);
    }

    private static final Logger logger = LoggerFactory.getLogger(YamlProcessor.class);

    public enum ResolutionMethod {
        OVERRIDE, OVERRIDE_AND_IGNORE, FIRST_FOUND
    }

    private ResolutionMethod resolutionMethod = ResolutionMethod.OVERRIDE;

    private Resource[] resources = new Resource[0];

    private Map<String, String> documentMatchers = new HashMap<String, String>();

    private boolean matchDefault = true;

    /**
     * A map of document matchers allowing callers to selectively use only some
     * of the documents in a YAML resource. In
     * YAML documents are separated by
     * <code>---</code> lines, and each document is converted to properties before the match is made. E.g.
     *
     * <pre>
     * environment: dev
     * url: http://dev.bar.com
     * name: Developer Setup
     * ---
     * environment: prod
     * url:http://foo.bar.com
     * name: My Cool App
     * </pre>
     *
     * when mapped with <code>documentMatchers = {"environment": "prod"}</code>
     * would end up as
     *
     * <pre>
     * environment=prod
     * url=http://foo.bar.com
     * name=My Cool App
     * url=http://dev.bar.com
     * </pre>
     *
     * @param matchers a map of keys to value patterns (regular expressions)
     */
    public void setDocumentMatchers(Map<String, String> matchers) {
        this.documentMatchers = Collections.unmodifiableMap(matchers);
    }

    /**
     * Flag indicating that a document that contains none of the keys in the
     * {@link #setDocumentMatchers(Map) document
     * matchers} will nevertheless match.
     *
     * @param matchDefault the flag to set (default true)
     */
    public void setMatchDefault(boolean matchDefault) {
        this.matchDefault = matchDefault;
    }

    /**
     * Method to use for resolving resources. Each resource will be converted to
     * a Map, so this property is used to
     * decide which map entries to keep in the final output from this factory.
     * Possible values:
     * <ul>
     * <li><code>OVERRIDE</code> for replacing values from earlier in the list</li>
     * <li><code>OVERRIDE_AND_IGNORE</code> the same, but ignore IO errors
     * loading individual resources</li>
     * <li><code>FIRST_FOUND</code> if you want to take the first resource in
     * the list that exists and use just that.</li>
     * </ul>
     *
     *
     * @param resolutionMethod the resolution method to set. Defaults to
     *            OVERRIDE.
     */
    public void setResolutionMethod(ResolutionMethod resolutionMethod) {
        this.resolutionMethod = resolutionMethod;
    }

    /**
     * @param resources the resources to set
     */
    public void setResources(Resource[] resources) {
        this.resources = resources;
    }

    /**
     * Provides an opportunity for subclasses to process the Yaml parsed from
     * the supplied resources. Each resource is
     * parsed in turn and the documents inside checked against the
     * {@link #setDocumentMatchers(Map) matchers}. If a
     * document matches it is passed into the callback, along with its
     * representation as Properties. Depending on the
     * {@link #setResolutionMethod(ResolutionMethod)} not all of the documents
     * will be parsed.
     *
     * @param callback a callback to delegate to once matching documents are
     *            found
     */
    protected void process(MatchCallback callback) {
        Yaml yaml = new Yaml();
        boolean found = false;
        for (Resource resource : resources) {
            try {
                int count = 0;
                for (Object object : yaml.loadAll(resource.getInputStream())) {
                    if (resolutionMethod != ResolutionMethod.FIRST_FOUND || !found) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> map = (Map<String, Object>) object;
                        if (map != null) {
                            process(map, callback);
                            found = true;
                            count++;
                        }
                    }
                }

                logger.debug("Loaded " + count + " document" + (count > 1 ? "s" : "") + " from YAML resource: "
                    + resource);

                if (resolutionMethod == ResolutionMethod.FIRST_FOUND && found) {
                    // No need to load any more resources
                    break;
                }
            } catch (IOException e) {
                if (e instanceof FileNotFoundException && e.getMessage().contains("${APPLICATION_CONFIG_FILE}") &&
                    (resolutionMethod == ResolutionMethod.FIRST_FOUND
                        || resolutionMethod == ResolutionMethod.OVERRIDE_AND_IGNORE)) {
                    logger.debug("Could not load map from " + resource + ": " + e.getMessage());
                } else if (resolutionMethod == ResolutionMethod.FIRST_FOUND
                                || resolutionMethod == ResolutionMethod.OVERRIDE_AND_IGNORE) {
                    logger.warn("Could not load map from " + resource + ": " + e.getMessage());
                }
                else {
                    throw new IllegalStateException(e);
                }
            }
        }
    }

    private void process(Map<String, Object> map, MatchCallback callback) {
        Properties properties = new Properties();
        assignProperties(properties, map, null);
        if (documentMatchers.isEmpty()) {
            logger.debug("Merging document (no matchers set):\n" + prettyPrintYaml(redactValues(map)));
            callback.process(properties, map);
        }
        else {
            boolean keyFound = false;
            boolean valueFound = false;
            for (Entry<String, String> entry : documentMatchers.entrySet()) {
                String key = entry.getKey();
                String pattern = entry.getValue();
                if (properties.containsKey(key)) {
                    keyFound = true;
                    String value = properties.getProperty(key);
                    if (value.matches(pattern)) {
                        logger.debug("Matched document with " +
                                     key + "=" + value + " (pattern=/" +
                                     pattern + "/):\n" + prettyPrintYaml(redactValues(map))
                        );
                        callback.process(properties, map);
                        valueFound = true;
                        // No need to check for more matches
                        break;
                    }
                }
            }
            if (!keyFound && matchDefault) {
                logger.debug("Matched document with default matcher:\n" + prettyPrintYaml(redactValues(map)));
                callback.process(properties, map);
            }
            else if (!valueFound) {
                logger.debug("Unmatched document");
            }
        }
    }

    private void assignProperties(Properties properties, Map<String, Object> input, String path) {
        for (Entry<String, Object> entry : input.entrySet()) {
            String key = entry.getKey();
            if (StringUtils.hasText(path)) {
                if (key.startsWith("[")) {
                    key = path + key;
                }
                else {
                    key = path + "." + key;
                }
            }
            Object value = entry.getValue();
            if (value instanceof String) {
                properties.put(key, value);
            }
            else if (value instanceof Map) {
                // Need a compound key
                @SuppressWarnings("unchecked")
                Map<String, Object> map = (Map<String, Object>) value;
                assignProperties(properties, map, key);
            }
            else if (value instanceof Collection) {
                // Need a compound key
                @SuppressWarnings("unchecked")
                Collection<Object> collection = (Collection<Object>) value;
                properties.put(key, StringUtils.collectionToCommaDelimitedString(collection));
                int count = 0;
                for (Object object : collection) {
                    assignProperties(properties, Collections.singletonMap("[" + (count++) + "]", object), key);
                }
            }
            else {
                properties.put(key, value == null ? "" : value);
            }
        }
    }

}
