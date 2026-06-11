module org.wildfly.security.http.util {

    requires org.jboss.logging;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.server;
    requires org.wildfly.security.http;
    requires org.wildfly.security.mechanism;
    requires org.wildfly.security.provider.util;
    requires org.wildfly.security.util;
    requires static org.jboss.logging.annotations;

    exports org.wildfly.security.http.util;
}
