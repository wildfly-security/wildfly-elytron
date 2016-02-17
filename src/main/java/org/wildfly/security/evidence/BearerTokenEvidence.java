package org.wildfly.security.evidence;

import org.wildfly.common.Assert;

/**
 * An {@link Evidence} that usually holds a bearer security token.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class BearerTokenEvidence implements Evidence {

    private final String token;

    public BearerTokenEvidence(String token) {
        this.token = Assert.checkNotNullParam("token", token);
    }

    public String getToken() {
        return this.token;
    }
}
