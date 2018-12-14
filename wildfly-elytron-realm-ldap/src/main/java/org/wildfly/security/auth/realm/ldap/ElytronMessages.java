/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.auth.realm.ldap;

import static org.jboss.logging.Logger.Level.WARN;

import java.security.spec.InvalidKeySpecException;

import javax.naming.NamingException;

import org.jboss.logging.BasicLogger;
import org.jboss.logging.Logger;
import org.jboss.logging.annotations.Cause;
import org.jboss.logging.annotations.LogMessage;
import org.jboss.logging.annotations.Message;
import org.jboss.logging.annotations.MessageLogger;
import org.wildfly.security.auth.server.RealmUnavailableException;

/**
 * Log messages and exceptions for Elytron.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
@MessageLogger(projectCode = "ELY", length = 5)
interface ElytronMessages extends BasicLogger {
    ElytronMessages log = Logger.getMessageLogger(ElytronMessages.class, "org.wildfly.security");

    @Message(id = 2, value = "Parameter %s is empty")
    IllegalArgumentException emptyParameter(String parameter);

    @Message(id = 3, value = "This builder has already been built")
    IllegalStateException builderAlreadyBuilt();

    @Message(id = 4, value = "Unrecognized algorithm \"%s\"")
    IllegalArgumentException unrecognizedAlgorithm(String algorithm);

    @LogMessage(level = WARN)
    @Message(id = 7, value = "Credential destroying failed")
    void credentialDestroyingFailed(@Cause Throwable cause);

    @Message(id = 1041, value = "Could not obtain credential")
    RuntimeException couldNotObtainCredential();

    @Message(id = 1042, value = "Could not obtain credential")
    RuntimeException couldNotObtainCredentialWithCause(@Cause Throwable cause);

    @Message(id = 1053, value = "Insufficient data to form a digest and a salt")
    InvalidKeySpecException insufficientDataToFormDigestAndSalt();

    @Message(id = 1054, value = "Invalid salt \"%s%s\"")
    IllegalArgumentException invalidSalt(char lo, char hi);

    @Message(id = 1055, value = "Invalid rounds \"%s%s%s%s\"")
    IllegalArgumentException invalidRounds(char b0, char b1, char b2, char b3);

    @Message(id = 1056, value = "Invalid salt \"%s%s%s%s\"")
    IllegalArgumentException invalidSalt(char b0, char b1, char b2, char b3);

    @Message(id = 1057, value = "No DirContext supplier set")
    IllegalStateException noDirContextSupplierSet();

    @Message(id = 1058, value = "No principal mapping definition")
    IllegalStateException noPrincipalMappingDefinition();

    @Message(id = 1060, value = "Could not obtain principal")
    RuntimeException couldNotObtainPrincipal();

    @Message(id = 1062, value = "No provider URL has been set")
    IllegalStateException noProviderUrlSet();

    @Message(id = 1064, value = "Invalid identity name")
    IllegalArgumentException invalidName();

    @Message(id = 1079, value = "Ldap-backed realm failed to obtain attributes for entry [%s]")
    RuntimeException ldapRealmFailedObtainAttributes(String dn, @Cause Throwable cause);

    @Message(id = 1080, value = "Attribute [%s] value [%s] must be in X.500 format in order to obtain RDN [%s].")
    RuntimeException ldapRealmInvalidRdnForAttribute(String attributeName, String value, String rdn, @Cause Throwable cause);

    @Message(id = 1083, value = "Ldap-backed realm cannot to obtain not existing identity \"%s\"")
    RealmUnavailableException ldapRealmIdentityNotExists(String identity);

    @Message(id = 1084, value = "Error while consuming results from search. SearchDn [%s], Filter [%s], Filter Args [%s].")
    RuntimeException ldapRealmErrorWhileConsumingResultsFromSearch(String searchDn, String filter, String filterArgs, @Cause Throwable cause);

    @Message(id = 1085, value = "LDAP realm persister does not support given credential type")
    RealmUnavailableException ldapRealmsPersisterNotSupported();

    @Message(id = 1086, value = "Persisting credential %s into Ldap-backed realm failed. Identity dn: \"%s\"")
    RealmUnavailableException ldapRealmCredentialPersistingFailed(String credential, String dn, @Cause Throwable cause);

    @Message(id = 1087, value = "Clearing credentials from Ldap-backed realm failed. Identity dn: \"%s\"")
    RealmUnavailableException ldapRealmCredentialClearingFailed(String dn, @Cause Throwable cause);

    @Message(id = 1090, value = "Unknown LDAP password scheme")
    InvalidKeySpecException unknownLdapPasswordScheme();

    @Message(id = 1096, value = "No such identity")
    RealmUnavailableException noSuchIdentity();

    @Message(id = 1097, value = "Ldap-backed realm failed to delete identity from server")
    RealmUnavailableException ldapRealmFailedDeleteIdentityFromServer(@Cause Throwable cause);

    @Message(id = 1098, value = "Ldap-backed realm failed to create identity on server")
    RealmUnavailableException ldapRealmFailedCreateIdentityOnServer(@Cause Throwable cause);

    @Message(id = 1099, value = "Ldap-backed realm is not configured to allow create new identities (new identity parent and attributes has to be set)")
    RealmUnavailableException ldapRealmNotConfiguredToSupportCreatingIdentities();

    @Message(id = 1100, value = "Ldap-backed realm does not contain mapping to set Elytron attribute \"%s\" of identity \"%s\"")
    RealmUnavailableException ldapRealmCannotSetAttributeWithoutMapping(String attribute, String identity);

    @LogMessage(level = WARN)
    @Message(id = 1101, value = "Ldap-backed realm does not support setting of filtered attribute \"%s\" (identity \"%s\")")
    void ldapRealmDoesNotSupportSettingFilteredAttribute(String attribute, String identity);

    @Message(id = 1102, value = "Ldap-backed realm requires exactly one value of attribute \"%s\" mapped to RDN (identity \"%s\")")
    RealmUnavailableException ldapRealmRequiresExactlyOneRdnAttribute(String attribute, String identity);

    @Message(id = 1103, value = "Ldap-backed realm failed to set attributes of identity \"%s\"")
    RealmUnavailableException ldapRealmAttributesSettingFailed(String identity, @Cause Throwable cause);

    @Message(id = 1108, value = "Ldap-backed realm identity search failed")
    RealmUnavailableException ldapRealmIdentitySearchFailed(@Cause Throwable cause);

    @Message(id = 1109, value = "Ldap-backed realm is not configured to allow iterate over identities (iterator filter has to be set)")
    RealmUnavailableException ldapRealmNotConfiguredToSupportIteratingOverIdentities();

    @Message(id = 1125, value = "Ldap-backed realm failed to obtain context")
    RealmUnavailableException ldapRealmFailedToObtainContext(@Cause Throwable cause);

    @LogMessage
    @Message(id = 1146, value = "LDAP Realm unable to register listener, defering action.")
    void ldapRealmDeferRegistration();

    @Message(id = 1147, value = "Invalid LDAP name [%s]")
    RuntimeException ldapInvalidLdapName(String name, @Cause Throwable cause);

    @Message(id = 1150, value = "Obtaining DirContext credentials from AuthenticationContext failed.")
    NamingException obtainingDirContextCredentialFromAuthenticationContextFailed(@Cause Throwable cause);

    @Message(id = 1153, value = "Direct LDAP verification failed with DN [%s] and absolute DN [%s]")
    RealmUnavailableException directLdapVerificationFailed(String distinguishedName, String absoluteName, @Cause Exception e);

    @Message(id = 4025, value = "DirContext tries to connect without ThreadLocalSSLSocketFactory thread local setting")
    IllegalStateException threadLocalSslSocketFactoryThreadLocalNotSet();
}
