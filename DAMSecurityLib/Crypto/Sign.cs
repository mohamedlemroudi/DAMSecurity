using DAMSecurityLib.Certificates;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using iText.Kernel.Pdf;
using iText.Signatures;
using iText.Bouncycastle.Crypto;
using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography;
using System.Text;
using iText.Kernel.Geom;
using iText.Forms.Fields.Properties;
using iText.Forms.Form.Element;
using System.Runtime.CompilerServices;

namespace DAMSecurityLib.Crypto
{
    /// <summary>
    /// This class is used to sign documents 
    /// </summary>
    public class Sign
    {

        #region Private attributes

        private X509Certificate2? certificate;
        private Certificates.CertificateInfo? certificateInfo;
        private Pkcs12Store pkcs12Store = new Pkcs12StoreBuilder().Build();
        private string storeAlias = "";

        #endregion

        /// <summary>
        /// Init class certificate attributes with the disk certificate
        /// </summary>
        /// <param name="pfxFileName">Certificate file disk path</param>
        /// <param name="pfxPassword">Certificate password</param>
        public void InitCertificate(string pfxFileName, string pfxPassword)
        {
            certificate = new X509Certificate2(pfxFileName, pfxPassword);

            pkcs12Store.Load(new FileStream(pfxFileName, FileMode.Open, FileAccess.Read), pfxPassword.ToCharArray());
            foreach (string currentAlias in pkcs12Store.Aliases)
            {
                if (pkcs12Store.IsKeyEntry(currentAlias))
                {
                    storeAlias = currentAlias;
                    break;
                }
            }
            certificateInfo = Certificates.CertificateInfo.FromCertificate(pfxFileName,pfxPassword);
        }

        /// <summary>
        /// Sign pdf document and save result to disk.
        /// This method puts digital signature inside pdf document
        /// </summary>
        /// <param name="inputFileName">Input pdf file path to sign</param>
        /// <param name="outputFileName">Ouput pdf file path to save the result file</param>
        /// <param name="showSignature">If signatature is visible in pdf document</param>
        public void SignPdf(string inputFileName, string outputFileName, bool showSignature)
        {
            FileStream fs = new FileStream(inputFileName, FileMode.Open, FileAccess.Read);
            SignPdf(fs, outputFileName, showSignature);
        }

        /// <summary>
        /// Sign pdf document and save result to disk.
        /// This method puts a digital signature inside a pdf document.
        /// </summary>
        /// <param name="inputPdfStream">Input pdf stream to sign</param>
        /// <param name="outputFileName">Output pdf file path to save the result</param>
        /// <param name="showSignature">If signature is visible in pdf document</param>
        public void SignPdf(Stream inputPdfStream, string outputFileName, bool showSignature)
        {
            AsymmetricKeyParameter key = pkcs12Store.GetKey(storeAlias).Key;

            X509CertificateEntry[] chainEntries = pkcs12Store.GetCertificateChain(storeAlias);
            IX509Certificate[] chain = new IX509Certificate[chainEntries.Length];
            for (int i = 0; i < chainEntries.Length; i++)
                chain[i] = new X509CertificateBC(chainEntries[i].Certificate);
            PrivateKeySignature signature = new PrivateKeySignature(new PrivateKeyBC(key), "SHA256");

            using (PdfReader pdfReader = new PdfReader(inputPdfStream))
            using (FileStream result = File.Create(outputFileName))
            {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().UseAppendMode());

                if (showSignature)
                {
                    CreateSignatureApperanceField(pdfSigner);
                }

                pdfSigner.SignDetached(signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
            }
        }

        /// <summary>
        /// Sign filedisk file with the global class certificate
        /// </summary>
        /// <param name="inputFileName">Filedisk input file path to sign</param>
        /// <param name="outputFileName">Filedisk output file path to save the result</param>
        public void SignFile(string inputFileName, string outputFileName)
        {
            if (certificate != null)
            {
                byte[] inputBytes = File.ReadAllBytes(inputFileName);
                byte[] outputBytes = SignDocument(certificate, inputBytes);

                File.WriteAllBytes(outputFileName, outputBytes);
            }
        }

        /// <summary>
        /// Returns SHA-256 HASH from input byte array
        /// </summary>
        /// <param name="input">Input byte array to obtain SHA-256 HASH</param>
        /// <returns>SHA-256 HASH</returns>
        public string SHA256Hash(byte[] input)
        {
            using (SHA256 sHA256 = SHA256.Create())
            {
                byte[] hashBytes = sHA256.ComputeHash(input);
                StringBuilder builder = new StringBuilder();

                foreach (byte b in hashBytes)
                {
                    builder.Append(b.ToString("x2"));
                }

                return builder.ToString();
            }
        }


        /// <summary>
        /// Sign byte array document with the certificate
        /// </summary>
        /// <param name="certificate">Certificated used to sign the document</param>
        /// <param name="document">Document byte array to sign</param>
        /// <returns>Byte array with the signed document</returns>
        internal static byte[] SignDocument(X509Certificate2 certificate, byte[] document)
        {
            ContentInfo contentInfo = new ContentInfo(document);
            SignedCms signedCms = new SignedCms(contentInfo, false);
            CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate);
            signedCms.ComputeSignature(signer);

            return signedCms.Encode();
        }

        /// <summary>
        /// Adds signature field rectangle inside pdf document
        /// </summary>
        /// <param name="pdfSigner">PdfSigner used to sign document</param>
        internal void CreateSignatureApperanceField(PdfSigner pdfSigner)
        {
            var pdfDocument = pdfSigner.GetDocument();
            var pageRect = pdfDocument.GetPage(1).GetPageSize();
            var size = new PageSize(pageRect);
            pdfDocument.AddNewPage(size);
            var totalPages = pdfDocument.GetNumberOfPages();
            float yPos = pdfDocument.GetPage(totalPages).GetPageSize().GetHeight() - 100;
            float xPos = 0;
            Rectangle rect = new Rectangle(xPos, yPos, 200, 100);

            pdfSigner.SetFieldName("signature");

            SignatureFieldAppearance appearance = new SignatureFieldAppearance(pdfSigner.GetFieldName())
                    .SetContent(new SignedAppearanceText()
                        .SetSignedBy(certificateInfo?.Organization)
                        .SetReasonLine("" + " - " + "")
                        .SetLocationLine("Location: " + certificateInfo?.Locality)
                        .SetSignDate(pdfSigner.GetSignDate()));

            pdfSigner.SetPageNumber(totalPages).SetPageRect(rect)
                    .SetSignatureAppearance(appearance);

        }
    }
}
