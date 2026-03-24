module org.wildfly.security.password.impl {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.asn1;
    requires org.wildfly.security.credential;
    requires org.wildfly.security.util;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.password.impl;
}
