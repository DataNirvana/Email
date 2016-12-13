using System;
using System.Text;

//----------------------------------------------------------------------------------------------------------------------------------------------------------------
/* 
    * Cpi.Net.SecureMail
    * Code is based on this great open project by Pete Everett - 
    * http://www.codeproject.com/Articles/41727/An-S-MIME-Library-for-Sending-Signed-and-Encrypted
*/
namespace MGL.Security.Email {
    //----------------------------------------------------------------------------------------------------------------------------------------------------------------
    internal class SecureMessageContent {
        # region Constructors

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        public SecureMessageContent(byte[] body, SecureContentType contentType, SecureTransferEncoding transferEncoding, bool encodeBody) {
            if (encodeBody) {
                switch (transferEncoding) {
                    case SecureTransferEncoding.QuotedPrintable:
                        Body = Encoding.ASCII.GetBytes(TransferEncoder.ToQuotedPrintable(body, false));
                        break;
                    case SecureTransferEncoding.Base64:
                        Body = Encoding.ASCII.GetBytes(TransferEncoder.ToBase64(body));
                        break;
                    case SecureTransferEncoding.SevenBit:
                        Body = body;
                        break;
                    default:
                        throw new ArgumentOutOfRangeException("transferEncoding", "Invalid Transfer Encoding");
                }
            } else {
                Body = body;
            }

            TransferEncoding = transferEncoding;
            ContentType = contentType;
        }

        # endregion

        # region Properties

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        public SecureContentType ContentType {
            get;
            private set;
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        public SecureTransferEncoding TransferEncoding {
            get;
            private set;
        }

        //----------------------------------------------------------------------------------------------------------------------------------------------------------------
        public byte[] Body {
            get;
            private set;
        }

        # endregion
    }
}
