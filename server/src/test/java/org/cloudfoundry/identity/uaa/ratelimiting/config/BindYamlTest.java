package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BindYamlTest {

    @Test
    void removeLeadingEmptyDocuments() {
        assertThat(BindYaml.removeLeadingEmptyDocuments(null)).isNull();
        assertThat(BindYaml.removeLeadingEmptyDocuments("")).isEmpty();
        assertThat(BindYaml.removeLeadingEmptyDocuments("\n--- \n--- {} \n---\n{}")).isEmpty();
        assertThat(BindYaml.removeLeadingEmptyDocuments("--- \nname: Fred")).isEqualTo("name: Fred");
    }

    @Test
    void bind() {
        BindYaml<Point> binder = new BindYaml<>(Point.class, "test");
        assertThat(binder.bind("")).isNull();
        assertThat(binder.bind("x : 1")).hasToString("(1,0)");
        assertThat(binder.bind("y : 2")).hasToString("(0,2)");
        assertThat(binder.bind("z : 3")).hasToString("(0,0,3)");
        assertThat(binder.bind("""
                x : 1
                y : 2
                z : 3""")).hasToString("(1,2,3)");
    }

    public static class Point {
        public int x;
        public int y;
        public Integer z;

        public Point(int x, int y, Integer z) {
            this.x = x;
            this.y = y;
            this.z = z;
        }

        public Point(int x, int y) {
            this(x, y, null);
        }

        public Point() {
            this(0, 0);
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder().append('(').append(x).append(',').append(y);
            if (z != null) {
                sb.append(',').append(z);
            }
            return sb.append(')').toString();
        }
    }
}