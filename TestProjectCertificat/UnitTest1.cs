namespace TestProjectCertificat
{
    [TestFixture]
    public class Tests
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void InitCertificate_LoadsCertificateAndFindStoreAlias()
        {
            // Arrange 
            //DAMSecurityLib.Crypto.Sign sign = new DAMSecurityLib.Crypto.Sign();
            //Crypto.Sign certificateManager = new DAMSecurityLib.Crypto.Sign();
            string pfxFileName = "C:\\Users\\Moha\\source\\repos\\DAMSecurity\\certificat.pfx";
            string pfxPassword = "patata123";

            // Act
            //certificateManager.In
        }
    }
}