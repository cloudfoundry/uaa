package org.cloudfoundry.identity.uaa.home;

import org.cloudfoundry.identity.uaa.UaaProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;

@Component
public class BuildInfo implements InitializingBean {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final String uaaUrl;
    private String version;
    private String commitId;
    private String timestamp;

    public BuildInfo(UaaProperties.Uaa properties) {
        this.uaaUrl = properties.url();
    }

    @Override
    public void afterPropertiesSet() {
        try {
            Properties gitProperties = PropertiesLoaderUtils.loadAllProperties("git.properties");
            commitId = gitProperties.getProperty("git.commit.id.abbrev", "UNKNOWN");
            String currentTime = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date());
            timestamp = gitProperties.getProperty("git.commit.time", currentTime);
        } catch (IOException e) {
            logger.debug("Exception loading git.properties", e);
        }
        try {
            Properties buildProperties = PropertiesLoaderUtils.loadAllProperties("build.properties");
            version = buildProperties.getProperty("build.version");
        } catch (IOException e) {
            logger.debug("Exception loading build.properties", e);
        }
        Assert.hasText(uaaUrl, "[Assertion failed] - uaaUrl must have text; it must not be null, empty, or blank");
        Assert.hasText(version, "[Assertion failed] - version must have text; it must not be null, empty, or blank");
        Assert.hasText(commitId, "[Assertion failed] - commitId must have text; it must not be null, empty, or blank");
        Assert.hasText(timestamp, "[Assertion failed] - timestamp must have text; it must not be null, empty, or blank");
    }

    public String getVersion() {
        return version;
    }

    public String getCommitId() {
        return commitId;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getUaaUrl() {
        return uaaUrl;
    }
}
