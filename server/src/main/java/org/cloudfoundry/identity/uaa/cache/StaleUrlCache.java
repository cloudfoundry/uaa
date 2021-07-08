package org.cloudfoundry.identity.uaa.cache;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Ticker;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;

import org.cloudfoundry.identity.uaa.util.TimeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

@Component
public class StaleUrlCache implements UrlContentCache {
  private static final Logger logger = LoggerFactory.getLogger(StaleUrlCache.class);
  private static final int DEFAULT_MAX_ENTRIES = 10_000;

  private final Duration cacheExpiration;
  private final LoadingCache<UriRequest, CacheEntry> cache;

  @Autowired
  public StaleUrlCache(final TimeService timeService) {
    this(timeService, Ticker.systemTicker());
  }

  public StaleUrlCache(final TimeService timeService, final Ticker ticker) {
    this(Duration.ofMinutes(10), timeService, DEFAULT_MAX_ENTRIES, ticker);
  }

  public StaleUrlCache(final Duration cacheExpiration, final TimeService timeService, final int maxEntries,
      final Ticker ticker) {
    this.cacheExpiration = cacheExpiration;
    this.cache = CacheBuilder.newBuilder().refreshAfterWrite(this.cacheExpiration.toMillis(), TimeUnit.MILLISECONDS)
        .maximumSize(maxEntries).ticker(ticker).build(new UrlCacheLoader(timeService));
  }

  @Override
  public byte[] getUrlContent(String uri, final RestTemplate template) {
    return getUrlContent(uri, template, HttpMethod.GET, null);
  }

  @Override
  public byte[] getUrlContent(String uri, final RestTemplate template, final HttpMethod method,
      HttpEntity<?> requestEntity) {
    try {
      return cache.get(new UriRequest(uri, template, method, requestEntity)).data;
    } catch (UncheckedExecutionException e) {
      logger.warn("UncheckedException " + e.getMessage() + e);
      throw (RuntimeException) e.getCause();
    } catch (ExecutionException e) {
      logger.warn("ExecutionException " + e.getMessage() + e);
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public void clear() {
    cache.invalidateAll();
  }

  @Override
  public long size() {
    return cache.size();
  }

  static class UriRequest {
    final String uri;
    final RestTemplate template;
    final HttpMethod method;
    final HttpEntity<?> requestEntity;

    UriRequest(String uri, RestTemplate template, HttpMethod method, HttpEntity<?> requestEntity) {
      this.uri = uri;
      this.template = template;
      this.method = method;
      this.requestEntity = requestEntity;
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + ((uri == null) ? 0 : uri.hashCode());
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (obj == null) {
        return false;
      }
      if (getClass() != obj.getClass()) {
        return false;
      }
      UriRequest other = (UriRequest) obj;
      if (uri == null) {
        if (other.uri != null) {
          return false;
        }
      } else if (!uri.equals(other.uri)) {
        return false;
      }
      return true;
    }
  }

  static class CacheEntry {
    final Instant timeEntered;
    final byte[] data;

    CacheEntry(Instant timeEntered, byte[] data) {
      this.timeEntered = timeEntered;
      this.data = data;
    }

  }

  class UrlCacheLoader extends CacheLoader<UriRequest, CacheEntry> {

    private final TimeService timeService;

    UrlCacheLoader(TimeService timeService) {
      this.timeService = timeService;
    }

    @Override
    public CacheEntry load(UriRequest request) throws RuntimeException {
      try {
        byte[] metadata;
        final URI netUri = new URI(request.uri);
        if (request.requestEntity != null) {
          ResponseEntity<byte[]> responseEntity = request.template.exchange(netUri, request.method,
              request.requestEntity, byte[].class);
          if (responseEntity.getStatusCode() == HttpStatus.OK) {
            metadata = responseEntity.getBody();
          } else {
            throw new IllegalArgumentException(
                "Unable to fetch content, status:" + responseEntity.getStatusCode().getReasonPhrase());
          }
        } else {
          metadata = request.template.getForObject(netUri, byte[].class);
        }
        Instant now = Instant.ofEpochMilli(timeService.getCurrentTimeMillis());
        return new CacheEntry(now, metadata);
      } catch (RestClientException x) {
        logger.warn("Unable to fetch metadata for {0}. {1}", request.uri, x.getMessage());
        throw x;
      } catch (URISyntaxException e) {
        throw new IllegalArgumentException(e);
      }
    }

  }
}
