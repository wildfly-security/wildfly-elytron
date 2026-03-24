module org.wildfly.security.util {

    requires java.naming;
    requires org.wildfly.common;
    requires org.wildfly.security.asn1;
    requires org.wildfly.security;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.util;
}
