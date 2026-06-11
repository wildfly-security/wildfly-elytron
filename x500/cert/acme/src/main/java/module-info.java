module org.wildfly.security.x500.cert.acme {

    requires org.wildfly.common;
    requires org.wildfly.security.asn1;
    requires org.wildfly.security.x500.cert.util;
    requires org.wildfly.security.x500.cert;
    requires org.wildfly.security.x500;
    requires org.wildfly.security;
    requires static jakarta.json;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.x500.cert.acme;
}
