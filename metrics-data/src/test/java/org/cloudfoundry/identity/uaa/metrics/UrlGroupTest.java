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

        assertThat(map)
                .containsEntry("group", "group")
                .containsEntry("category", "category")
                .containsEntry("limit", 1L)
                .containsEntry("pattern", "/**");
    }

    @Test
    void from() {
        group = UrlGroup.from(map);
        assertThat(group.getGroup()).isEqualTo("group");
        assertThat(group.getCategory()).isEqualTo("category");
        assertThat(group.getLimit()).isOne();
        assertThat(group.getPattern()).isEqualTo("/**");
    }
}