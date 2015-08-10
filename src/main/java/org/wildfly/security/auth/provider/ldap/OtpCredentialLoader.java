package org.wildfly.security.auth.provider.ldap;

import org.wildfly.common.Assert;
import org.wildfly.security._private.ElytronMessages;
import org.wildfly.security.auth.server.CredentialSupport;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.OneTimePasswordSpec;
import org.wildfly.security.util.Alphabet;
import org.wildfly.security.util.CodePointIterator;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * A {@link CredentialLoader} for loading OTP credentials stored within defined attributes of LDAP entries.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
public class OtpCredentialLoader implements CredentialLoader {

    private final String algorithmAttributeName;
    private final String hashAttributeName;
    private final String seedAttributeName;
    private final String sequenceAttributeName;

    public OtpCredentialLoader(String algorithmAttributeName, String hashAttributeName, String seedAttributeName, String sequenceAttributeName) {
        Assert.assertNotNull(algorithmAttributeName);
        Assert.assertNotNull(hashAttributeName);
        Assert.assertNotNull(seedAttributeName);
        Assert.assertNotNull(sequenceAttributeName);
        this.algorithmAttributeName = algorithmAttributeName;
        this.hashAttributeName = hashAttributeName;
        this.seedAttributeName = seedAttributeName;
        this.sequenceAttributeName = sequenceAttributeName;
    }

    @Override public CredentialSupport getCredentialSupport(DirContextFactory contextFactory, Class<?> credentialType) {
        return credentialType == OneTimePassword.class ? CredentialSupport.UNKNOWN : CredentialSupport.UNSUPPORTED;
    }

    @Override
    public IdentityCredentialLoader forIdentity(DirContextFactory contextFactory, String distinguishedName) {
        return new ForIdentityLoader(contextFactory, distinguishedName);
    }

    private class ForIdentityLoader implements IdentityCredentialLoader {

        private final DirContextFactory contextFactory;
        private final String distinguishedName;

        public ForIdentityLoader(DirContextFactory contextFactory, String distinguishedName) {
            this.contextFactory = contextFactory;
            this.distinguishedName = distinguishedName;
        }

        @Override
        public CredentialSupport getCredentialSupport(Class<?> credentialType) {
            Object credential = getCredential(credentialType);
            // By this point it is either supported or it isn't - no in-between.
            if (credential != null && credentialType.isInstance(credential)) {
                return CredentialSupport.FULLY_SUPPORTED;
            }

            return CredentialSupport.UNSUPPORTED;
        }

        @Override
        public <C> C getCredential(Class<C> credentialType) {
            DirContext context = null;
            try {
                context = contextFactory.obtainDirContext(null);

                Attributes attributes = context.getAttributes(distinguishedName,
                        new String[] { algorithmAttributeName, hashAttributeName, seedAttributeName, sequenceAttributeName });
                Attribute algorithmAttribute = attributes.get(algorithmAttributeName);
                Attribute hashAttribute = attributes.get(hashAttributeName);
                Attribute seedAttribute = attributes.get(seedAttributeName);
                Attribute sequenceAttribute = attributes.get(sequenceAttributeName);

                if (algorithmAttribute == null || hashAttribute == null || seedAttribute == null || sequenceAttribute == null) {
                    return null;
                }

                PasswordFactory passwordFactory = PasswordFactory.getInstance(((String) algorithmAttribute.get()));
                Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(
                                CodePointIterator.ofString((String) hashAttribute.get())
                                        .base64Decode(Alphabet.Base64Alphabet.STANDARD, false).drain(),
                                CodePointIterator.ofString((String) seedAttribute.get())
                                        .base64Decode(Alphabet.Base64Alphabet.STANDARD, false).drain(),
                                Integer.valueOf((String) sequenceAttribute.get())));
                if (credentialType.isInstance(password)) {
                    return credentialType.cast(password);
                }

            } catch (NamingException | InvalidKeySpecException | NoSuchAlgorithmException e) {
                if (ElytronMessages.log.isTraceEnabled()) ElytronMessages.log.trace("Getting OTP credential of type "
                        + credentialType.getName() + " failed. dn=" + distinguishedName, e);
            } finally {
                contextFactory.returnContext(context);
            }
            return null;
        }
    }
}
