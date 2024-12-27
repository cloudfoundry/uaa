package org.cloudfoundry.identity.uaa.ratelimiting.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BindYamlTest {

    @Test
    void removeLeadingEmptyDocuments() {
        assertNull(BindYaml.removeLeadingEmptyDocuments(null));
        assertEquals("", BindYaml.removeLeadingEmptyDocuments(""));
        assertEquals("", BindYaml.removeLeadingEmptyDocuments("\n--- \n--- {} \n---\n{}"));
        assertEquals("name: Fred", BindYaml.removeLeadingEmptyDocuments("--- \nname: Fred"));
    }

    @Test
    void bind() {
        BindYaml<Point> binder = new BindYaml<>( Point.class, "test" );
        assertNull(binder.bind(""));
        assertEquals("(1,0)", binder.bind("x : 1").toString());
        assertEquals("(0,2)", binder.bind("y : 2").toString());
        assertEquals("(0,0,3)", binder.bind("z : 3").toString());
        assertEquals("(1,2,3)", binder.bind("""
                x : 1
                y : 2
                z : 3""").toString());
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