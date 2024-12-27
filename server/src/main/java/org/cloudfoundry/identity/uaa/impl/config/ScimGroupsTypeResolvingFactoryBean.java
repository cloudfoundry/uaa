package org.cloudfoundry.identity.uaa.impl.config;

import org.cloudfoundry.identity.uaa.util.MapCollector;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class ScimGroupsTypeResolvingFactoryBean {

    public ScimGroupsTypeResolvingFactoryBean(Object o) {
        if (o instanceof String string) {
            groups = StringUtils.commaDelimitedListToSet(string).stream()
                    .map(g -> g.split("\\|"))
                    .collect(new MapCollector<>(
                            gd -> gd[0],
                            gd -> gd.length > 1 ? gd[1] : null)
                    );
        } else {
            groups = new HashMap<>((Map<String, String>) o);
        }
    }

    private HashMap<String, String> groups;

    public HashMap<String, String> getGroups() {
        return groups;
    }

    public void setGroups(HashMap<String, String> groups) {
        this.groups = groups;
    }
}
