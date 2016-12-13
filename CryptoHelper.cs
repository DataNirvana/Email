﻿using System;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

//----------------------------------------------------------------------------------------------------------------------------------------------------------------
/* 
    * Cpi.Net.SecureMail
    * Code is based on this great open project by Pete Everett - 
    * http://www.codeproject.com/Articles/41727/An-S-MIME-Library-for-Sending-Signed-and-Encrypted
*/
namespace MGL.Security.Email {

    //----------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    /// Provides methods for performing commonly-used cryptographic tasks
    /// </summary>
    public static class CryptoHelper {

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// Generates a cryptographic signature for a given message
        /// </summary>
        /// <param name="message">The message to sign</param>
        /// <param name="signingCertificate">The certificate to sign the message with</param>
        /// <param name="encryptionCertificate">An optional encryption certificate to include along with the signature</param>
        /// <returns>The signature for the specified message</returns>
        internal static byte[] GetSignature(string message, X509Certificate2 signingCertificate, X509Certificate2 encryptionCertificate) {
            
            byte[] messageBytes = Encoding.ASCII.GetBytes(message);
            ContentInfo content = new ContentInfo(messageBytes);
            
            SignedCms signedCms = new SignedCms(content, true);

            CmsSigner cmsSigner = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, signingCertificate);

            // 29-Aug-2015 - Beef up the digest algorithm to use the same as the algorithm itself ...
            // Note that this needs to be the same as the micalg which is set in SecureEmailMessage.SecureMessageContent
            // Otherwise the certificate will potentially warn that this is a problem and that the certificate has been tampered with
            // in e.g. clients like thunderbird (outlook doesnt seem to flag this as an issue)
            // https://tools.ietf.org/html/rfc5751
            // The value of the micalg parameter is dependent on the message digest algorithm(s) , (which does NOT use hyphens)
            // hence the friendly name in the OID has no hyphen
            // The values to be placed in the micalg parameter SHOULD be from the following:  sha-1, sha-224, sha-256, sha-384, sha-512
            cmsSigner.DigestAlgorithm = MGLSecureEmailer.DigitalSignatureDigestOID;

            cmsSigner.IncludeOption = X509IncludeOption.WholeChain;

            if (encryptionCertificate != null) {
                cmsSigner.Certificates.Add(encryptionCertificate);
            }

            Pkcs9SigningTime signingTime = new Pkcs9SigningTime();
            cmsSigner.SignedAttributes.Add(signingTime);

            // 29-Aug-2015 - We want the signature to be computed silently, so reset this value to be true (was originally false) ...
            signedCms.ComputeSignature(cmsSigner, true ); // false);

            return signedCms.Encode();
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// Encrypts a message
        /// </summary>
        /// <param name="message">The message to encrypt</param>
        /// <param name="encryptionCertificates">A list of certificates to encrypt the message with</param>
        /// <returns>The encrypted message</returns>
        internal static byte[] EncryptMessage(string message, X509Certificate2Collection encryptionCertificates) {
            byte[] messageBytes = Encoding.ASCII.GetBytes(message);

            EnvelopedCms envelopedCms = new EnvelopedCms(new ContentInfo(messageBytes));

            CmsRecipientCollection recipients = new CmsRecipientCollection(SubjectIdentifierType.IssuerAndSerialNumber, encryptionCertificates);

            envelopedCms.Encrypt(recipients);

            return envelopedCms.Encode();
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// Finds a certificates in the user's local store based on its serial number
        /// </summary>
        /// <param name="serialNumber">The serial number of the certificate to retrieve</param>
        /// <returns>The requested certificate, or null if the certificate is not found</returns>
        public static X509Certificate2 FindCertificate(string serialNumber) {
            X509Store localStore = new X509Store(StoreName.My);

            localStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            try {
                X509Certificate2Collection matches = localStore.Certificates.Find(
                    X509FindType.FindBySerialNumber,
                    serialNumber,
                    true);

                if (matches.Count > 0) {
                    return matches[0];
                } else {
                    return null;
                }
            } finally {
                localStore.Close();
            }

        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        /// Finds a certificate in the user's local store based on its subject and usage flags
        /// </summary>
        /// <param name="subjectDistinguishedName">The subject distinguished name of the certificate</param>
        /// <param name="usage">The minimum usage flags the certificate must contain</param>
        /// <returns>The requested certificate, or null if the certificate is not found</returns>
        public static X509Certificate2 FindCertificate(string subjectDistinguishedName, X509KeyUsageFlags usage) {
            X509Store localStore = new X509Store(StoreName.My);

            localStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            try {
                X509Certificate2Collection matches = localStore.Certificates.Find(
                    X509FindType.FindBySubjectDistinguishedName,
                    subjectDistinguishedName,
                    true);

                if (matches.Count > 0) {
                    foreach (X509Certificate2 cert in matches) {
                        foreach (X509Extension extension in cert.Extensions) {
                            X509KeyUsageExtension usageExtension = extension as X509KeyUsageExtension;

                            if (usageExtension != null) {
                                bool matchesUsageRequirements = ((usage & usageExtension.KeyUsages) == usage);

                                if (matchesUsageRequirements) {
                                    return cert;
                                }
                            }
                        }
                    }

                    return null;
                } else {
                    return null;
                }
            } finally {
                localStore.Close();
            }
        }
    }
}
