module org.wildfly.security.sasl.auth.util {

    requires java.security.sasl;
    requires org.wildfly.common;
    requires org.wildfly.security.auth.client;
    requires org.wildfly.security.sasl;

    exports org.wildfly.security.sasl.auth.util;
}
