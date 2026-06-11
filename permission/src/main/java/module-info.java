module org.wildfly.security.permission {

    requires org.jboss.logging;
    requires org.wildfly.common;
    requires org.wildfly.security.util;
    requires static org.jboss.logging.annotations;

    exports org.wildfly.security.permission;
}
