package org.cloudfoundry.identity.uaa.metrics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class UrlGroupTest {

    Map<String, Object> map;
    UrlGroup group;

    @BeforeEach
    void setup() {
        group = new UrlGroup();
        group.setGroup("group");
        group.setCategory("category");
        group.setLimit(1);
        group.setPattern("/**");
        map = group.getMap();
    }
    @Test
    void getMap() {

        assertThat(map.get("group")).isEqualTo("group");
        assertThat(map.get("category")).isEqualTo("category");
        assertThat(map.get("limit")).isEqualTo(1L);
        assertThat(map.get("pattern")).isEqualTo("/**");
    }

    @Test
    void from() {
        group = UrlGroup.from(map);
        assertThat(group.getGroup()).isEqualTo("group");
        assertThat(group.getCategory()).isEqualTo("category");
        assertThat(group.getLimit()).isEqualTo(1L);
        assertThat(group.getPattern()).isEqualTo("/**");
    }
}