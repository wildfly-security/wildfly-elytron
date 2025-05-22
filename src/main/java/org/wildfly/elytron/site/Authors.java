package org.wildfly.elytron.site;

import java.util.Map;

public record Authors(Map<String, Author> map) {
    public record Author(String name, String emailHash, String bio) { }
}
