using System;

//----------------------------------------------------------------------------------------------------------------------------------------------------------------
/* 
    * Cpi.Net.SecureMail
    * Code is based on this great open project by Pete Everett - 
    * http://www.codeproject.com/Articles/41727/An-S-MIME-Library-for-Sending-Signed-and-Encrypted
*/
namespace MGL.Security.Email {

    //----------------------------------------------------------------------------------------------------------------------------------------------------------------
    /// <summary>
    /// Specifies the priority of a SecureMailMessage.
    /// </summary>
    public enum SecureMailPriority {
        /// <summary>
        /// The e-mail has normal priority.
        /// </summary>
        Normal,
        /// <summary>
        /// The e-mail has low priority.
        /// </summary>
        Low,
        /// <summary>
        /// The e-mail has high priority.
        /// </summary>
        High
    }
}
