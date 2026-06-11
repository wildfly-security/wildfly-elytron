module org.wildfly.security.jose.jwk {

    requires com.fasterxml.jackson.annotation;
    requires org.wildfly.common;
    requires org.wildfly.security.jose.util;
    requires org.wildfly.security.x500.cert;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.jose.jwk;
}
