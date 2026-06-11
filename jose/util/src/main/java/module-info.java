module org.wildfly.security.jose.util {

    requires transitive com.fasterxml.jackson.annotation;
    requires transitive com.fasterxml.jackson.core;
    requires transitive com.fasterxml.jackson.databind;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.jose.util;
}
