module org.wildfly.security.ssh.util {

    requires org.apache.sshd.common;
    requires org.wildfly.common;
    requires org.wildfly.security.x500.cert;
    requires static org.jboss.logging.annotations;
    requires static org.jboss.logging;

    exports org.wildfly.security.ssh.util;
}
