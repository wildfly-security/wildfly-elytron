module org.wildfly.security.x500 {

    requires org.wildfly.common;
    requires org.wildfly.security.asn1;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.x500;
    exports org.wildfly.security.x500.util;
}
