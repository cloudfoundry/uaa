package org.cloudfoundry.identity.uaa.cache;


import org.springframework.web.client.RestTemplate;

import java.net.URI;

public interface UrlContentCache {

    /**
     * Retrieves and caches the content for a given URI by invoking
     * {@link org.springframework.web.client.RestTemplate#getForObject(URI, Class)} method.
     * The template may throw {@link org.springframework.web.client.RestClientException} to indicate content not available
     * @param uri - must be a valid URI
     * @param template - RestTemplate used for content retrieval
     * @return byte[] for the content or null if a content retrieval error happened ({@link org.springframework.web.client.RestClientException})
     * @throws IllegalArgumentException if uri is not valid {@link URI}
     */
    byte[] getUrlContent(String uri, RestTemplate template);

    /**
     * Clears the cache unconditionally
     */
    void clear();

    /**
     * Returns the current number of entries in the cache
     * @return the number of entries in the cache
     */
    long size();
}
