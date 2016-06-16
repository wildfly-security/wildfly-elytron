package org.wildfly.security.auth.realm.ldap;

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

    private final String algorithmAttributeName;
    private final String hashAttributeName;
    private final String seedAttributeName;
    private final String sequenceAttributeName;

    OtpCredentialLoader(String algorithmAttributeName, String hashAttributeName, String seedAttributeName, String sequenceAttributeName) {
        Assert.checkNotNullParam("algorithmAttributeName", algorithmAttributeName);
        Assert.checkNotNullParam("hashAttributeName", hashAttributeName);
        Assert.checkNotNullParam("seedAttributeName", seedAttributeName);
        Assert.checkNotNullParam("sequenceAttributeName", sequenceAttributeName);
        this.algorithmAttributeName = algorithmAttributeName;
        this.hashAttributeName = hashAttributeName;
        this.seedAttributeName = seedAttributeName;
        this.sequenceAttributeName = sequenceAttributeName;
    }

    @Override
    public SupportLevel getCredentialAcquireSupport(final DirContextFactory contextFactory, final Class<? extends Credential> credentialType, final String algorithmName) {
        if (credentialType == PasswordCredential.class) {
            if (algorithmName == null) {
                return SupportLevel.SUPPORTED;
            }
            switch (algorithmName) {
                case OneTimePassword.ALGORITHM_OTP_MD5: return SupportLevel.POSSIBLY_SUPPORTED;
                case OneTimePassword.ALGORITHM_OTP_SHA1: return SupportLevel.POSSIBLY_SUPPORTED;
                default: return SupportLevel.UNSUPPORTED;
            }
        }
        return SupportLevel.UNSUPPORTED;
    }

    @Override
    public ForIdentityLoader forIdentity(DirContextFactory contextFactory, String distinguishedName) {
        return new ForIdentityLoader(contextFactory, distinguishedName);
    }

    private class ForIdentityLoader implements IdentityCredentialPersister {

        private final DirContextFactory contextFactory;
        private final String distinguishedName;

        public ForIdentityLoader(DirContextFactory contextFactory, String distinguishedName) {
            this.contextFactory = contextFactory;
            this.distinguishedName = distinguishedName;
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(final Class<? extends Credential> credentialType, final String algorithmName) {
            if (credentialType != PasswordCredential.class) {
                return SupportLevel.UNSUPPORTED;
            }
            DirContext context = null;
            try {
                context = contextFactory.obtainDirContext(null);
            } catch (NamingException e) {
                if (log.isTraceEnabled()) log.trace("Getting otp credential " + credentialType.getName() + " failed. dn=" + distinguishedName, e);
            }
            try {
                Attributes attributes = context.getAttributes(distinguishedName,
                        new String[] { algorithmAttributeName, hashAttributeName, seedAttributeName, sequenceAttributeName });
                Attribute algorithmAttribute = attributes.get(algorithmAttributeName);
                Attribute hashAttribute = attributes.get(hashAttributeName);
                Attribute seedAttribute = attributes.get(seedAttributeName);
                Attribute sequenceAttribute = attributes.get(sequenceAttributeName);

                if (algorithmAttribute != null && hashAttribute != null && seedAttribute != null && sequenceAttribute != null && (algorithmName == null || algorithmAttribute.contains(algorithmName))) {
                    return SupportLevel.SUPPORTED;
                }

            } catch (NamingException e) {
                if (log.isTraceEnabled()) log.trace("Getting otp credential " + credentialType.getName() + " failed. dn=" + distinguishedName, e);
            } finally {
                contextFactory.returnContext(context);
            }
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public <C extends Credential> C getCredential(final Class<C> credentialType, final String algorithmName) {
            if (credentialType != PasswordCredential.class) {
                return null;
            }

            DirContext context;
            try {
                context = contextFactory.obtainDirContext(null);
            }
            catch (NamingException e) {
                if (log.isTraceEnabled()) log.trace("Getting OTP credential of type "
                        + credentialType.getName() + " failed. dn=" + distinguishedName, e);
                return null;
            }
            try {
                Attributes attributes = context.getAttributes(distinguishedName,
                        new String[] { algorithmAttributeName, hashAttributeName, seedAttributeName, sequenceAttributeName });
                Attribute algorithmAttribute = attributes.get(algorithmAttributeName);
                Attribute hashAttribute = attributes.get(hashAttributeName);
                Attribute seedAttribute = attributes.get(seedAttributeName);
                Attribute sequenceAttribute = attributes.get(sequenceAttributeName);

                if (algorithmAttribute == null || algorithmName != null && ! algorithmAttribute.contains(algorithmName) || hashAttribute == null || seedAttribute == null || sequenceAttribute == null) {
                    return null;
                }

                PasswordFactory passwordFactory = PasswordFactory.getInstance((String) algorithmAttribute.get());
                Password password = passwordFactory.generatePassword(new OneTimePasswordSpec(
                                CodePointIterator.ofString((String) hashAttribute.get())
                                        .base64Decode(Alphabet.Base64Alphabet.STANDARD, false).drain(),
                                CodePointIterator.ofString((String) seedAttribute.get())
                                        .base64Decode(Alphabet.Base64Alphabet.STANDARD, false).drain(),
                                Integer.parseInt((String) sequenceAttribute.get())));
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
        public boolean getCredentialPersistSupport(final Class<? extends Credential> credentialType, final String algorithmName) {
            return OtpCredentialLoader.this.getCredentialAcquireSupport(contextFactory, credentialType, algorithmName).mayBeSupported();
        }

        @Override
        public void persistCredential(final Credential credential) throws RealmUnavailableException {
            OneTimePassword password = credential.castAndApply(PasswordCredential.class, c -> c.getPassword(OneTimePassword.class));
            DirContext context;
            try {
                context = contextFactory.obtainDirContext(null);
            } catch (NamingException e) {
                throw log.ldapRealmCredentialPersistingFailed(credential.toString(), distinguishedName, e);
            }
            try {
                Attributes attributes = new BasicAttributes();
                attributes.put(algorithmAttributeName, password.getAlgorithm());
                attributes.put(hashAttributeName, ByteIterator.ofBytes(password.getHash()).base64Encode().drainToString());
                attributes.put(seedAttributeName, ByteIterator.ofBytes(password.getSeed()).base64Encode().drainToString());
                attributes.put(sequenceAttributeName, Integer.toString(password.getSequenceNumber()));

                context.modifyAttributes(distinguishedName, DirContext.REPLACE_ATTRIBUTE, attributes);
            } catch (NamingException e) {
                throw log.ldapRealmCredentialPersistingFailed(credential.toString(), distinguishedName, e);
            } finally {
                contextFactory.returnContext(context);
            }
        }

        @Override public void clearCredentials() throws RealmUnavailableException {
            DirContext context;
            try {
                context = contextFactory.obtainDirContext(null);
            } catch (NamingException e) {
                throw log.ldapRealmCredentialClearingFailed(distinguishedName, e);
            }
            try {
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
