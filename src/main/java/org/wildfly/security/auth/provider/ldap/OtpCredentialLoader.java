package org.wildfly.security.auth.provider.ldap;

import org.wildfly.common.Assert;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.auth.server.SupportLevel;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.interfaces.OneTimePassword;
import org.wildfly.security.password.spec.OneTimePasswordSpec;
import org.wildfly.security.util.Alphabet;
import org.wildfly.security.util.ByteIterator;
import org.wildfly.security.util.CodePointIterator;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.NoSuchAttributeException;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.wildfly.security._private.ElytronMessages.log;

/**
 * A {@link CredentialLoader} for loading OTP credentials stored within defined attributes of LDAP entries.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
class OtpCredentialLoader implements CredentialPersister {

    public static final String DEFAULT_CREDENTIAL_NAME = "otp";

    private final String myCredentialName; // name of credential defined by following LDAP attributes
    private final String algorithmAttributeName;
    private final String hashAttributeName;
    private final String seedAttributeName;
    private final String sequenceAttributeName;

    OtpCredentialLoader(String credentialName, String algorithmAttributeName, String hashAttributeName, String seedAttributeName, String sequenceAttributeName) {
        Assert.checkNotNullParam("credentialName", credentialName);
        Assert.checkNotNullParam("algorithmAttributeName", algorithmAttributeName);
        Assert.checkNotNullParam("hashAttributeName", hashAttributeName);
        Assert.checkNotNullParam("seedAttributeName", seedAttributeName);
        Assert.checkNotNullParam("sequenceAttributeName", sequenceAttributeName);
        this.myCredentialName = credentialName;
        this.algorithmAttributeName = algorithmAttributeName;
        this.hashAttributeName = hashAttributeName;
        this.seedAttributeName = seedAttributeName;
        this.sequenceAttributeName = sequenceAttributeName;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(DirContextFactory contextFactory, String credentialName) {
        return myCredentialName.equals(credentialName) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
    }

    @Override
    public ForIdentityLoader forIdentity(DirContextFactory contextFactory, String distinguishedName) {
        return new ForIdentityLoader(contextFactory, distinguishedName);
    }

    private class ForIdentityLoader implements IdentityCredentialLoader, IdentityCredentialPersister {

        private final DirContextFactory contextFactory;
        private final String distinguishedName;

        public ForIdentityLoader(DirContextFactory contextFactory, String distinguishedName) {
            this.contextFactory = contextFactory;
            this.distinguishedName = distinguishedName;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(String credentialName) {
            if ( ! OtpCredentialLoader.this.myCredentialName.equals(credentialName)) {
                return SupportLevel.UNSUPPORTED;
            }
            DirContext context = null;
            try {
                context = contextFactory.obtainDirContext(null);

                Attributes attributes = context.getAttributes(distinguishedName,
                        new String[] { algorithmAttributeName, hashAttributeName, seedAttributeName, sequenceAttributeName });
                Attribute algorithmAttribute = attributes.get(algorithmAttributeName);
                Attribute hashAttribute = attributes.get(hashAttributeName);
                Attribute seedAttribute = attributes.get(seedAttributeName);
                Attribute sequenceAttribute = attributes.get(sequenceAttributeName);

                if (algorithmAttribute != null && hashAttribute != null && seedAttribute != null && sequenceAttribute != null) {
                    return SupportLevel.SUPPORTED;
                }

            } catch (NamingException e) {
                // ignored
            } finally {
                contextFactory.returnContext(context);
            }
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(String credentialName, Class<C> credentialType) {
            if ( ! OtpCredentialLoader.this.myCredentialName.equals(credentialName)) {
                return null;
            }
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
                if (credentialType.isAssignableFrom(PasswordCredential.class)) {
                    return credentialType.cast(new PasswordCredential(password));
                }

            } catch (NamingException | InvalidKeySpecException | NoSuchAlgorithmException e) {
                if (log.isTraceEnabled()) log.trace("Getting OTP credential of type "
                        + credentialType.getName() + " failed. dn=" + distinguishedName, e);
            } finally {
                contextFactory.returnContext(context);
            }
            return null;
        }

        @Override
        public boolean getCredentialPersistSupport(String credentialName) {
            return OtpCredentialLoader.this.myCredentialName.equals(credentialName);
        }

        @Override
        public void persistCredential(String credentialName, Credential credential) throws RealmUnavailableException {
            PasswordCredential passwordCredential = (PasswordCredential) credential;
            OneTimePassword password = (OneTimePassword) passwordCredential.getPassword();
            DirContext context = null;
            try {
                context = contextFactory.obtainDirContext(null);

                Attributes attributes = new BasicAttributes();
                attributes.put(algorithmAttributeName, password.getAlgorithm());
                attributes.put(hashAttributeName, ByteIterator.ofBytes(password.getHash()).base64Encode().drainToString());
                attributes.put(seedAttributeName, ByteIterator.ofBytes(password.getSeed()).base64Encode().drainToString());
                attributes.put(sequenceAttributeName, Integer.toString(password.getSequenceNumber()));

                context.modifyAttributes(distinguishedName, DirContext.REPLACE_ATTRIBUTE, attributes);
            } catch (NamingException e) {
                throw log.ldapRealmCredentialPersistingFailed(credential.toString(), credentialName, distinguishedName, e);
            } finally {
                contextFactory.returnContext(context);
            }
        }

        @Override public void clearCredentials() throws RealmUnavailableException {
            DirContext context = null;
            try {
                context = contextFactory.obtainDirContext(null);

                Attributes attributes = new BasicAttributes();
                attributes.put(new BasicAttribute(algorithmAttributeName));
                attributes.put(new BasicAttribute(hashAttributeName));
                attributes.put(new BasicAttribute(seedAttributeName));
                attributes.put(new BasicAttribute(sequenceAttributeName));

                context.modifyAttributes(distinguishedName, DirContext.REMOVE_ATTRIBUTE, attributes);
            } catch (NoSuchAttributeException e) {
                // ignore if already clear
            } catch (NamingException e) {
                throw log.ldapRealmCredentialClearingFailed(distinguishedName, e);
            } finally {
                contextFactory.returnContext(context);
            }
        }
    }
}
