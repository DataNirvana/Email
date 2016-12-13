using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Mail;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;
using System.IO;
using System.Net.Mime;
using System.Security;
using System.Runtime.InteropServices;

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace MGL.Security.Email {

    //----------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    ///     Edgar Scrase - 29-August-2015
    ///     Updated Email class to replace the MGL.Data.DataUtilities.MGLEmailer class, which does not support encrypted or signed emails
    ///     Uses the code produced by Pete Everett - Cpi.Net.SecureMail, which is a set of good and simple classes for encrypting and signing
    ///     emails.
    ///     http://www.codeproject.com/Articles/41727/An-S-MIME-Library-for-Sending-Signed-and-Encrypted
    /// </summary>
    public class MGLSecureEmailer {

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static SecureString defaultFromMailAddress = null;
        public static SecureString FromMailAddress {
            get { return defaultFromMailAddress; }
            set { defaultFromMailAddress = value; }
        }
        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static SecureString defaultFromMailAddressName = null;
        public static SecureString FromMailAddressName {
            get { return defaultFromMailAddressName; }
            set { defaultFromMailAddressName = value; }
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static string defaultSMTPHost = "post.wizards.co.uk";
        public static string SMTPHost {
            get { return defaultSMTPHost; }
            set { defaultSMTPHost = value; }
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static SecureString defaultSMTPUsername = null;
        public static SecureString SMTPUsername {
            get { return defaultSMTPUsername; }
            set { defaultSMTPUsername = value; }
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static SecureString defaultSMTPPassword = null;
        public static SecureString SMTPPassword {
            get { return defaultSMTPPassword; }
            set { defaultSMTPPassword = value; }
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static int defaultSMTPPort = 587; // originally 25, but lets default to using SSL now it is 2015
        public static int SMTPPort {
            get { return defaultSMTPPort; }
            set { defaultSMTPPort = value; }
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static bool enableSSL = true; // originally false, but lets default to using SSL now it is 2015
        public static bool EnableSSL {
            get { return enableSSL; }
            set { enableSSL = value; }
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static bool bodyIsHTML = true; // originally false, but lets always try to use HTML now it is 2015
        public static bool BodyIsHTML {
            get { return bodyIsHTML; }
            set { bodyIsHTML = value; }
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        // Added to accomodate the signature certificate from the sender
        // If we are going to use this class for encryption in the future, we would also need the from AND to encryption certificates...
        private static SecureString digitalSignatureFile = null;
        /// <summary>
        ///     The Digital Signature certificate file related to the from email address in PFX format
        /// </summary>
        public static SecureString DigitalSignatureFile {
            get { return digitalSignatureFile; }
            set { digitalSignatureFile = value; }
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static System.Security.Cryptography.Oid digitalSignatureDigestOID;
        /// <summary>
        ///     Currently supported are SHA1, SHA256 and SHA512
        ///     http://www.oid-info.com/get/2.16.840.1.101.3.4.2.1
        ///     System.Security.Cryptography.Oid("2.16.840.1.101.3.4.2.1", "SHA256")
        ///     SHA512 - 2.16.840.1.101.3.4.2.3
        /// </summary>
        public static System.Security.Cryptography.Oid DigitalSignatureDigestOID {
            get { return digitalSignatureDigestOID; }
            set { digitalSignatureDigestOID = value; }
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static Exception lastException = null;
        public static Exception LastException {
            get { return lastException; }
            set { lastException = value; }
        }


        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///    Sends an email signed with a digital signature specified by the X509 certificate file name supplied in the DigitalSignatureFile
        ///    property
        /// </summary>
        /// <param name="toMailAddress"></param>
        /// <param name="toName">Leave blank "" for default</param>
        /// <param name="subject"></param>
        /// <param name="body"></param>
        /// <param name="SMTPHost">Leave blank "" for default</param>
        /// <param name="SMTPUsername">Leave blank "" for default</param>
        /// <param name="SMTPPassword">Leave blank "" for default</param>
        /// <param name="fromMailAddress">Leave blank "" for default</param>
        /// <param name="fromName">Leave blank "" for default</param>
        /// <param name="portID">Leave 0 default</param>
        /// <param name="EnableSSL"></param>
        /// <returns>True if the email was sent successfully</returns>
        public static bool SendEmail(
            StringBuilder toMailAddress, StringBuilder toName,
            string subject, string body,
            string SMTPHost, SecureString SMTPUsername, SecureString SMTPPassword,
            SecureString fromMailAddress, SecureString fromName,
            int portID, bool EnableSSL) {


            bool isSuccess = true;
            // instantiate here so we can use the finally block to clean up this message ...
            SecureMailMessage message = null;
            X509Certificate2 myCert = null;

            try {

                //_____0_____ Check the SMTP details ...
                CheckSMTPDetails(ref fromMailAddress, ref fromName, ref SMTPHost, ref SMTPUsername, ref SMTPPassword, ref portID);

                //_____1_____ Lets start the message - note we just want to add the from, to and subject for now
                // If this email is to be signed then we need to keep the body blank ...
                message = new SecureMailMessage();

                // Load the recipient's encryption cert from a file.
                myCert = new X509Certificate2(MGLSecureEmailer.Decrypt( digitalSignatureFile).ToString());

                // Get the digest for this certificate ...
                SetDigest(myCert);

                // Set the from and to user - note that we can add multiple users with this email format
                message.From = new SecureMailAddress(
                    MGLSecureEmailer.Decrypt(fromMailAddress).ToString(),
                    MGLSecureEmailer.Decrypt(fromName).ToString(), null, myCert);

                message.To.Add(new SecureMailAddress(toMailAddress.ToString(), toName.ToString(), null));
                //message.To.Add(new SecureMailAddress("unhcr.pakIMTeam@gmail.com", "Pak IM Team", null));

                // Add the subject
                message.Subject = subject;

                // Add the body
                message.Body = body;
                message.IsBodyHtml = bodyIsHTML;

                // We currently ONLY want to SIGN the email, not encrypt it, so set these two values appropriately
                // (and we ALWAYS want to sign it) ...
                message.IsSigned = true;
                message.IsEncrypted = false;


                //_____2_____ Setup the SMTP client
                System.Net.Mail.SmtpClient smtpClient = new SmtpClient(SMTPHost);

                // The checkSMTPDetails method above has already tried to check if the portID is zero or less
                // So will already be the default value if this is the case, so we can roll right on
                smtpClient = new SmtpClient(SMTPHost, portID);

                // Sort the credentials to be used for the SMTP connection out
                System.Net.NetworkCredential ncAuth = new System.Net.NetworkCredential(
                    MGLSecureEmailer.Decrypt( SMTPUsername).ToString(),
                    MGLSecureEmailer.Decrypt(SMTPPassword).ToString()
                );

                smtpClient.UseDefaultCredentials = false;
                smtpClient.Credentials = ncAuth;

                // To use ssl or not that is the question
                // With the SMTP connection we probably always now want to use SSL or even better, TLS
                if (EnableSSL || SMTPHost.Contains("gmail")) {
                    smtpClient.EnableSsl = true;
                }


                //_____3_____ Lets do it!  Send the email - this is neat as the SecureMailMessage can be cast as a MailMessage
                // which is the input that the smtpClient is expecting ...
                smtpClient.Send(message);


            } catch (Exception ex) {

                // Add the exception to the last exception property and ensure that the user knows this Email was not sent by returning false
                isSuccess = false;
                MGLSecureEmailer.LastException = ex;

            } finally {

                //_____4_____ And lastly, lets clean up everything that contains sensitive passwords or private keys
                if (message != null) {
                    message.Dispose();
                }

                // and lets also dispose of the certificate information that is being stored in memory ...
                if (myCert != null) {
                    myCert = null;
                    DigitalSignatureDigestOID = null;
                }

            }

            return isSuccess;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static void CheckSMTPDetails(
            ref SecureString fromMailAddress, ref SecureString fromName,
            ref string SMTPHost, ref SecureString SMTPUsername, ref SecureString SMTPPassword, ref int SMTPPort) {

            if (fromMailAddress == null || fromMailAddress.Length == 0) {
                fromMailAddress = defaultFromMailAddress;
            }
            if (fromName == null || fromName.Length == 0) {
                fromName = defaultFromMailAddressName;
            }

            if (string.IsNullOrEmpty(SMTPHost)) {
                SMTPHost = defaultSMTPHost;
            }
            if (SMTPUsername == null || SMTPUsername.Length == 0) {
                SMTPUsername = defaultSMTPUsername;
            }
            if (SMTPPassword == null || SMTPPassword.Length == 0) {
                SMTPPassword = defaultSMTPPassword;
            }
            if (SMTPPort <= 0) {
                SMTPPort = defaultSMTPPort;
            }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        private static bool SetDigest( X509Certificate2 x509Cert ) {
            bool success = false;

            if (x509Cert != null) {

                string name = x509Cert.SignatureAlgorithm.FriendlyName;
                if (name != null) {
                    // Really we want to prefer the SHA2 algorithms if possible, of which SHA512 is the best ...
                    // See https://en.wikipedia.org/wiki/SHA-2 for more background
                    // SHA1 has been officially DEPRECATED as of 2013 - https://en.wikipedia.org/wiki/SHA-1
                    if (name.ToLower().Contains("sha512") == true) {
                        MGLSecureEmailer.DigitalSignatureDigestOID
                            = new System.Security.Cryptography.Oid("2.16.840.1.101.3.4.2.3", "sha512" );

                    } else if (name.ToLower().Contains("sha256") == true) {
                        MGLSecureEmailer.DigitalSignatureDigestOID
                            = new System.Security.Cryptography.Oid("2.16.840.1.101.3.4.2.1", "sha256");

                    } else {
                        // Go with the shitty SHA1!
                        MGLSecureEmailer.DigitalSignatureDigestOID = new System.Security.Cryptography.Oid("1.3.14.3.2.26", "sha1");
                    }

                    success = true;
                }
            }

            return success;
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------
        /// <summary>
        ///     Returning a StringBuilder means the information CAN be cleared in VM before being returned
        ///     Copied from SecureStringWrapper for ease ...
        /// </summary>
        public static StringBuilder Decrypt(SecureString secureStr) {
            IntPtr str = IntPtr.Zero;
            try {
                str = Marshal.SecureStringToGlobalAllocUnicode(secureStr);
                StringBuilder s = new StringBuilder(Marshal.PtrToStringUni(str));
                return s;
            } finally {
                // it is critical that this is in a finally block so that it always runs and removes the pointer to the string
                Marshal.ZeroFreeGlobalAllocUnicode(str);
            }
        }


        //---------------------------------------------------------------------------------------------------------------------------------------------------------------
        public static bool Test() {

            MGLSecureEmailer.BodyIsHTML = true;
            MGLSecureEmailer.DigitalSignatureFile = new SecureString();
            foreach (char c in "C:/Docs/OpenSSL_DataNirvana/UNHCRPakIMTeam/UNHCRPakIMTeamCertificate.pfx".ToCharArray()) {
                MGLSecureEmailer.DigitalSignatureFile.AppendChar(c);
            }

            string username = "unhcr.pakIMTeam@gmail.com";
            SecureString userSS = new SecureString();
            foreach ( char c in username.ToCharArray()) {
                userSS.AppendChar( c );
            }

            string password = "";
            SecureString pwordSS = new SecureString();
            foreach ( char c in password.ToCharArray()) {
                pwordSS.AppendChar( c );
            }

            SecureString userNameSS = new SecureString();
            foreach (char c in "Pak IM Team".ToCharArray()) {
                userNameSS.AppendChar(c);
            }

            bool success = MGLSecureEmailer.SendEmail(
                new StringBuilder("unhcr.pakIMTeam@gmail.com"),
                new StringBuilder("Pak IM Team"),
                "Testing the MGLSecureEmailer",
                "And Hi<br />This is indeed a test<br />Forget the rest<br />MGLSecureEmailer is <b>best</b>!",
                "smtp.gmail.com", userSS, pwordSS,
                userSS, userNameSS, 587, true);

            return success;
        }


    }
}

