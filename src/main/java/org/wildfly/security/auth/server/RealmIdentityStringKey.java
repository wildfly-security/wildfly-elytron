package org.wildfly.security.auth.server;

import java.io.Serializable;
import java.util.Objects;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class RealmIdentityStringKey implements RealmIdentity.Key, Serializable {

    private static final long serialVersionUID = 2172224748609255352L;

    private final String value;

    public RealmIdentityStringKey(String value) {
        this.value = value;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof RealmIdentity.Key)) return false;
        RealmIdentity.Key that = (RealmIdentity.Key) o;
        return Objects.equals(value, that.asString());
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
