/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of LocalController <https://github.com/OpenChargingCloud/LocalController>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Diagnostics;
using System.Security.Cryptography;

using Newtonsoft.Json;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Operators;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using WWCP = cloud.charging.open.protocols.WWCP;
using cloud.charging.open.protocols.WWCP.NetworkingNode;

using OCPPv1_6 = cloud.charging.open.protocols.OCPPv1_6;
using OCPPv2_1 = cloud.charging.open.protocols.OCPPv2_1;
using cloud.charging.open.protocols.OCPPv2_1.LocalController;

#endregion

namespace cloud.charging.open.LocalController.CLI
{

    /// <summary>
    /// A Local Controller.
    /// </summary>
    public class Program
    {

        #region (class) CommandException

        public class CommandException(String Message) : Exception(Message)
        {

            #region (static) NotWithinOCPPv1_6

            public static CommandException NotWithinOCPPv1_6
                => new ("This command ist not available within OCPP v1.6!");

            #endregion

        }

        #endregion

        #region Data

        private const           String         debugLogFile      = "debug.log";
        private const           String         ocppVersion1_6    = "v1.6";
        private const           String         ocppVersion2_1    = "v2.1";

        private static readonly SemaphoreSlim  cliLock           = new (1, 1);
        private static readonly SemaphoreSlim  logfileLock1_6    = new (1, 1);
        private static readonly SemaphoreSlim  logfileLock2_6    = new (1, 1);

        private readonly static String         logfileNameV1_6   = Path.Combine(AppContext.BaseDirectory, "OCPPv1.6_Messages.log");
        private readonly static String         logfileNameV2_1   = Path.Combine(AppContext.BaseDirectory, "OCPPv2.1_Messages.log");

        #endregion


        private static async Task DebugLog(String             Message,
                                           CancellationToken  CancellationToken)
        {

            try
            {
                await cliLock.WaitAsync(CancellationToken);
                DebugX.Log(Message);
            }
            catch (Exception e)
            {
                //DebugX.LogException(e, $"{nameof(testCSMSv2_1)}.{nameof(testCSMSv2_1.OnNewTCPConnection)}");
                DebugX.LogException(e, $"{nameof(DebugLog)}");
            }
            finally
            {
                cliLock.Release();
            }

        }


        private static async Task Log(String             LogFileName,
                                      String             Message,
                                      SemaphoreSlim      LogFileLock,
                                      CancellationToken  CancellationToken)
        {

            var retry = 0;

            do
            {
                try
                {

                    retry++;

                    await LogFileLock.WaitAsync(CancellationToken);

                    await File.AppendAllTextAsync(
                             LogFileName,
                             Message + Environment.NewLine,
                             CancellationToken
                         );

                }
                catch (Exception e)
                {
                    DebugX.LogException(e, $"{nameof(WriteToLogfileV2_1)}");
                }
                finally
                {
                    LogFileLock.Release();
                }


            }
            while (retry > 3);

        }

        private static Task WriteToLogfileV2_1(String             Message,
                                               CancellationToken  CancellationToken)

            => Log(logfileNameV2_1,
                   Message,
                   logfileLock2_6,
                   CancellationToken);


        #region ToDotNet(this Certificate, PrivateKey = null)

        static ECDsa ToDotNetECDsa(ECPrivateKeyParameters privateKeyParameters)
        {

            var domainParameters  = privateKeyParameters.Parameters;
            var curveParams       = domainParameters.Curve;
            var q                 = domainParameters.G.Multiply(privateKeyParameters.D).Normalize();

            var ecdsa             = ECDsa.Create(new ECParameters() {
                                        Curve  = ECCurve.CreateFromOid(new Oid(curveParams.ToString() ?? "")),
                                        D      = privateKeyParameters.D.ToByteArrayUnsigned(),
                                        Q      = new ECPoint {
                                                     X = q.AffineXCoord.GetEncoded(),
                                                     Y = q.AffineYCoord.GetEncoded()
                                                 }
                                    });

            return ecdsa;

        }


        /// <summary>
        /// Convert the Bouncy Castle certificate to a .NET certificate.
        /// </summary>
        /// <param name="Certificate">A Bouncy Castle certificate.</param>
        /// <param name="PrivateKey">An optional private key to be included.</param>
        static System.Security.Cryptography.X509Certificates.X509Certificate2? ToDotNet(X509Certificate                Certificate,
                                                                                        AsymmetricKeyParameter?        PrivateKey       = null,
                                                                                        IEnumerable<X509Certificate>?  CACertificates   = null)
        {

            if (PrivateKey is null)
                return new (Certificate.GetEncoded());

            if (PrivateKey is RsaPrivateCrtKeyParameters rsaPrivateKey)
            {

                var store             = new Pkcs12StoreBuilder().Build();
                var certificateEntry  = new X509CertificateEntry(Certificate);

                store.SetCertificateEntry(Certificate.SubjectDN.ToString(),
                                          certificateEntry);

                store.SetKeyEntry        (Certificate.SubjectDN.ToString(),
                                          new AsymmetricKeyEntry(rsaPrivateKey),
                                          [ certificateEntry ]);

                foreach (var caCertificate in (CACertificates ?? []))
                {
                    store.SetCertificateEntry(caCertificate.SubjectDN.ToString(),
                                              new X509CertificateEntry(caCertificate));
                }

                using (var pfxStream = new MemoryStream())
                {

                    var password = RandomExtensions.RandomString(10);

                    store.Save(pfxStream,
                               password.ToCharArray(),
                               new SecureRandom());

                    return new System.Security.Cryptography.X509Certificates.X509Certificate2(
                               pfxStream.ToArray(),
                               password,
                               System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable
                           );

                }

            }

            if (PrivateKey is ECPrivateKeyParameters eccPrivateKey)
            {

                //var dotNetCertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(Certificate.GetEncoded());
                //var ecdsa             = ToDotNetECDsa(eccPrivateKey);

                //return dotNetCertificate.CopyWithPrivateKey(ecdsa);

            }

            return null;

        }

        #endregion



        /// <summary>
        /// Start the OCPP Local Controller Application.
        /// </summary>
        /// <param name="Arguments">Command line arguments</param>
        public static async Task Main(String[] Arguments)
        {

            #region Data

            var dnsClient = new DNSClient(SearchForIPv6DNSServers: false);

            #endregion

            #region Debug to Console/file

            var debugFile    = new TextWriterTraceListener(debugLogFile);

            var debugTargets = new[] {
                debugFile,
                new TextWriterTraceListener(Console.Out)
            };

            Trace.Listeners.AddRange(debugTargets);

            #endregion


            #region Setup PKI

            #region Data

            AsymmetricCipherKeyPair? rootCA_ECC_KeyPair           = null;
            X509Certificate?         rootCA_ECC_Certificate       = null;
            AsymmetricCipherKeyPair? rootCA_RSA_KeyPair           = null;
            X509Certificate?         rootCA_RSA_Certificate       = null;

            AsymmetricCipherKeyPair? serverCA_ECC_KeyPair         = null;
            X509Certificate?         serverCA_ECC_Certificate     = null;
            AsymmetricCipherKeyPair? serverCA_RSA_KeyPair         = null;
            X509Certificate?         serverCA_RSA_Certificate     = null;

            AsymmetricCipherKeyPair? clientCA_ECC_KeyPair         = null;
            X509Certificate?         clientCA_ECC_Certificate     = null;
            AsymmetricCipherKeyPair? clientCA_RSA_KeyPair         = null;
            X509Certificate?         clientCA_RSA_Certificate     = null;

            AsymmetricCipherKeyPair? firmwareCA_ECC_KeyPair       = null;
            X509Certificate?         firmwareCA_ECC_Certificate   = null;
            AsymmetricCipherKeyPair? firmwareCA_RSA_KeyPair       = null;
            X509Certificate?         firmwareCA_RSA_Certificate   = null;


            AsymmetricCipherKeyPair? server1_ECC_KeyPair          = null;
            X509Certificate?         server1_ECC_Certificate      = null;
            AsymmetricCipherKeyPair? server1_RSA_KeyPair          = null;
            X509Certificate?         server1_RSA_Certificate      = null;


            AsymmetricCipherKeyPair? client1_ECC_KeyPair          = null;
            X509Certificate?         client1_ECC_Certificate      = null;
            AsymmetricCipherKeyPair? client1_RSA_KeyPair          = null;
            X509Certificate?         client1_RSA_Certificate      = null;

            #endregion

            #region Crypto defaults

            var secureRandom                    = new SecureRandom();
            var eccSignatureAlgorithm           = "SHA256withECDSA";
            var rsaSignatureAlgorithm           = "SHA256WithRSA";

            var eccCurve                        = ECNamedCurveTable.GetByName("secp256r1");
            var eccDomainParameters             = new ECDomainParameters(eccCurve.Curve, eccCurve.G, eccCurve.N, eccCurve.H, eccCurve.GetSeed());
            var eccKeyGenParams                 = new ECKeyGenerationParameters(eccDomainParameters, secureRandom);

            Directory.CreateDirectory(Path.Combine(AppContext.BaseDirectory, "pki"));
            var rootCA_ECC_privateKeyFile       = Path.Combine(AppContext.BaseDirectory, "pki", "rootCA_ECC.key");
            var rootCA_ECC_certificateFile      = Path.Combine(AppContext.BaseDirectory, "pki", "rootCA_ECC.cert");
            var rootCA_RSA_privateKeyFile       = Path.Combine(AppContext.BaseDirectory, "pki", "rootCA_RSA.key");
            var rootCA_RSA_certificateFile      = Path.Combine(AppContext.BaseDirectory, "pki", "rootCA_RSA.cert");

            var serverCA_ECC_privateKeyFile     = Path.Combine(AppContext.BaseDirectory, "pki", "serverCA_ECC.key");
            var serverCA_ECC_certificateFile    = Path.Combine(AppContext.BaseDirectory, "pki", "serverCA_ECC.cert");
            var serverCA_RSA_privateKeyFile     = Path.Combine(AppContext.BaseDirectory, "pki", "serverCA_RSA.key");
            var serverCA_RSA_certificateFile    = Path.Combine(AppContext.BaseDirectory, "pki", "serverCA_RSA.cert");

            var clientCA_ECC_privateKeyFile     = Path.Combine(AppContext.BaseDirectory, "pki", "clientCA_ECC.key");
            var clientCA_ECC_certificateFile    = Path.Combine(AppContext.BaseDirectory, "pki", "clientCA_ECC.cert");
            var clientCA_RSA_privateKeyFile     = Path.Combine(AppContext.BaseDirectory, "pki", "clientCA_RSA.key");
            var clientCA_RSA_certificateFile    = Path.Combine(AppContext.BaseDirectory, "pki", "clientCA_RSA.cert");

            var firmwareCA_ECC_privateKeyFile   = Path.Combine(AppContext.BaseDirectory, "pki", "firmwareCA_ECC.key");
            var firmwareCA_ECC_certificateFile  = Path.Combine(AppContext.BaseDirectory, "pki", "firmwareCA_ECC.cert");
            var firmwareCA_RSA_privateKeyFile   = Path.Combine(AppContext.BaseDirectory, "pki", "firmwareCA_RSA.key");
            var firmwareCA_RSA_certificateFile  = Path.Combine(AppContext.BaseDirectory, "pki", "firmwareCA_RSA.cert");

            // ----------------------------------------------------------------------------------------------------

            var server1_ECC_privateKeyFile      = Path.Combine(AppContext.BaseDirectory, "pki", "server1_ECC.key");
            var server1_ECC_certificateFile     = Path.Combine(AppContext.BaseDirectory, "pki", "server1_ECC.cert");
            var server1_ECC_pfx                 = Path.Combine(AppContext.BaseDirectory, "pki", "server1_ECC.pfx");

            var server1_RSA_privateKeyFile      = Path.Combine(AppContext.BaseDirectory, "pki", "server1_RSA.key");
            var server1_RSA_certificateFile     = Path.Combine(AppContext.BaseDirectory, "pki", "server1_RSA.cert");
            var server1_RSA_pfx                 = Path.Combine(AppContext.BaseDirectory, "pki", "server1_RSA.pfx");


            var client1_ECC_privateKeyFile      = Path.Combine(AppContext.BaseDirectory, "pki", "client1_ECC.key");
            var client1_ECC_certificateFile     = Path.Combine(AppContext.BaseDirectory, "pki", "client1_ECC.cert");

            var client1_RSA_privateKeyFile      = Path.Combine(AppContext.BaseDirectory, "pki", "client1_RSA.key");
            var client1_RSA_certificateFile     = Path.Combine(AppContext.BaseDirectory, "pki", "client1_RSA.cert");

            #endregion

            #region Try to reload crypto data from disc

            try
            {

                // Root CA
                using (var reader = File.OpenText(rootCA_ECC_privateKeyFile))
                {
                    rootCA_ECC_KeyPair          = (AsymmetricCipherKeyPair)   new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(rootCA_ECC_certificateFile))
                {
                    rootCA_ECC_Certificate      = (X509Certificate)           new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(rootCA_RSA_privateKeyFile))
                {
                    rootCA_RSA_KeyPair          = (AsymmetricCipherKeyPair)   new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(rootCA_RSA_certificateFile))
                {
                    rootCA_RSA_Certificate      = (X509Certificate)           new PemReader(reader).ReadObject();
                }


                // Server CA
                using (var reader = File.OpenText(serverCA_ECC_privateKeyFile))
                {
                    serverCA_ECC_KeyPair        = (AsymmetricCipherKeyPair) new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(serverCA_ECC_certificateFile))
                {
                    serverCA_ECC_Certificate    = (X509Certificate)         new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(serverCA_RSA_privateKeyFile))
                {
                    serverCA_RSA_KeyPair        = (AsymmetricCipherKeyPair) new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(serverCA_RSA_certificateFile))
                {
                    serverCA_RSA_Certificate    = (X509Certificate)         new PemReader(reader).ReadObject();
                }


                // Client CA
                using (var reader = File.OpenText(clientCA_ECC_privateKeyFile))
                {
                    clientCA_ECC_KeyPair        = (AsymmetricCipherKeyPair) new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(clientCA_ECC_certificateFile))
                {
                    clientCA_ECC_Certificate    = (X509Certificate)         new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(clientCA_RSA_privateKeyFile))
                {
                    clientCA_RSA_KeyPair        = (AsymmetricCipherKeyPair) new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(clientCA_RSA_certificateFile))
                {
                    clientCA_RSA_Certificate    = (X509Certificate)         new PemReader(reader).ReadObject();
                }


                // Firmware CA
                using (var reader = File.OpenText(firmwareCA_ECC_privateKeyFile))
                {
                    firmwareCA_ECC_KeyPair      = (AsymmetricCipherKeyPair) new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(firmwareCA_ECC_certificateFile))
                {
                    firmwareCA_ECC_Certificate  = (X509Certificate)         new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(firmwareCA_RSA_privateKeyFile))
                {
                    firmwareCA_RSA_KeyPair      = (AsymmetricCipherKeyPair) new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(firmwareCA_RSA_certificateFile))
                {
                    firmwareCA_RSA_Certificate  = (X509Certificate)         new PemReader(reader).ReadObject();
                }


                // Server #1
                using (var reader = File.OpenText(server1_ECC_privateKeyFile))
                {
                    server1_ECC_KeyPair         = (AsymmetricCipherKeyPair) new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(server1_ECC_certificateFile))
                {
                    server1_ECC_Certificate     = (X509Certificate)         new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(server1_RSA_privateKeyFile))
                {
                    server1_RSA_KeyPair         = (AsymmetricCipherKeyPair) new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(server1_RSA_certificateFile))
                {
                    server1_RSA_Certificate     = (X509Certificate)         new PemReader(reader).ReadObject();
                }


                // Client #1
                using (var reader = File.OpenText(client1_ECC_privateKeyFile))
                {
                    client1_ECC_KeyPair         = (AsymmetricCipherKeyPair) new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(client1_ECC_certificateFile))
                {
                    client1_ECC_Certificate     = (X509Certificate)         new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(client1_RSA_privateKeyFile))
                {
                    client1_RSA_KeyPair         = (AsymmetricCipherKeyPair) new PemReader(reader).ReadObject();
                }

                using (var reader = File.OpenText(client1_RSA_certificateFile))
                {
                    client1_RSA_Certificate     = (X509Certificate)         new PemReader(reader).ReadObject();
                }

            }
            catch
            { }

            #endregion


            if (rootCA_ECC_KeyPair         is null)
            {

                var keyPairGenerator = new ECKeyPairGenerator();
                keyPairGenerator.Init(eccKeyGenParams);
                rootCA_ECC_KeyPair = keyPairGenerator.GenerateKeyPair();

                using (var writer = new StreamWriter(rootCA_ECC_privateKeyFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(rootCA_ECC_KeyPair.Private);
                    pemWriter.Writer.Flush();
                }

            }

            if (rootCA_ECC_Certificate     is null)
            {

                var certificateGenerator  = new X509V3CertificateGenerator();
                var subjectDN             = new X509Name("CN=Open Charging Cloud - Root CA (ECC), O=GraphDefined GmbH, OU=TestCA, L=Jena, C=Germany");

                certificateGenerator.SetIssuerDN     (subjectDN); // self-signed
                certificateGenerator.SetSubjectDN    (subjectDN);
                certificateGenerator.SetNotBefore    (Timestamp.Now.AddDays (-3).DateTime);
                certificateGenerator.SetNotAfter     (Timestamp.Now.AddYears(23).DateTime);
                certificateGenerator.SetPublicKey    (rootCA_ECC_KeyPair.Public);
                certificateGenerator.SetSerialNumber (BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));

                certificateGenerator.AddExtension    (X509Extensions.BasicConstraints,
                                                      critical: true,
                                                      new BasicConstraints(cA: true));

                certificateGenerator.AddExtension    (X509Extensions.KeyUsage,
                                                      critical: true,
                                                      new KeyUsage(
                                                          KeyUsage.DigitalSignature |
                                                          KeyUsage.KeyCertSign |
                                                          KeyUsage.CrlSign
                                                      ));

                rootCA_ECC_Certificate = certificateGenerator.Generate(new Asn1SignatureFactory(eccSignatureAlgorithm, rootCA_ECC_KeyPair.Private, secureRandom));

                using (var writer = new StreamWriter(rootCA_ECC_certificateFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(rootCA_ECC_Certificate);
                    pemWriter.Writer.Flush();
                }

            }

            if (rootCA_RSA_KeyPair         is null)
            {

                var rsaKeyPairGenerator = new RsaKeyPairGenerator();
                rsaKeyPairGenerator.Init(new KeyGenerationParameters(secureRandom, 4096));
                rootCA_RSA_KeyPair = rsaKeyPairGenerator.GenerateKeyPair();

                using (var writer = new StreamWriter(rootCA_RSA_privateKeyFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(rootCA_RSA_KeyPair.Private);
                    pemWriter.Writer.Flush();
                }

            }

            if (rootCA_RSA_Certificate     is null)
            {

                var certificateGenerator  = new X509V3CertificateGenerator();
                var subjectDN             = new X509Name("CN=Open Charging Cloud - Root CA (RSA), O=GraphDefined GmbH, OU=TestCA, L=Jena, C=Germany");

                certificateGenerator.SetIssuerDN     (subjectDN); // self-signed
                certificateGenerator.SetSubjectDN    (subjectDN);
                certificateGenerator.SetNotBefore    (Timestamp.Now.AddDays (-3).DateTime);
                certificateGenerator.SetNotAfter     (Timestamp.Now.AddYears(23).DateTime);
                certificateGenerator.SetPublicKey    (rootCA_RSA_KeyPair.Public);
                certificateGenerator.SetSerialNumber (BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));

                certificateGenerator.AddExtension    (X509Extensions.BasicConstraints,
                                                      critical: true,
                                                      new BasicConstraints(cA: true));

                certificateGenerator.AddExtension    (X509Extensions.KeyUsage,
                                                      critical: true,
                                                      new KeyUsage(
                                                          KeyUsage.DigitalSignature |
                                                          KeyUsage.KeyCertSign |
                                                          KeyUsage.CrlSign
                                                      ));

                rootCA_RSA_Certificate = certificateGenerator.Generate(new Asn1SignatureFactory(rsaSignatureAlgorithm, rootCA_RSA_KeyPair.Private, secureRandom));

                using (var writer = new StreamWriter(rootCA_RSA_certificateFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(rootCA_RSA_Certificate);
                    pemWriter.Writer.Flush();
                }

            }


            if (serverCA_ECC_KeyPair       is null)
            {

                var keyPairGenerator = new ECKeyPairGenerator();
                keyPairGenerator.Init(eccKeyGenParams);
                serverCA_ECC_KeyPair = keyPairGenerator.GenerateKeyPair();

                using (var writer = new StreamWriter(serverCA_ECC_privateKeyFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(serverCA_ECC_KeyPair.Private);
                    pemWriter.Writer.Flush();
                }

            }

            if (serverCA_ECC_Certificate   is null)
            {

                var certificateGenerator  = new X509V3CertificateGenerator();

                certificateGenerator.SetIssuerDN     (new X509Name(rootCA_ECC_Certificate.SubjectDN.ToString()));
                certificateGenerator.SetSubjectDN    (new X509Name("CN=Open Charging Cloud - Server CA (ECC), O=GraphDefined GmbH, OU=TestCA, L=Jena, C=Germany"));
                certificateGenerator.SetNotBefore    (Timestamp.Now.AddDays (-2).DateTime);
                certificateGenerator.SetNotAfter     (Timestamp.Now.AddYears(+5).DateTime);
                certificateGenerator.SetPublicKey    (serverCA_ECC_KeyPair.Public);
                certificateGenerator.SetSerialNumber (BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));

                certificateGenerator.AddExtension    (X509Extensions.BasicConstraints,
                                                      critical: true,
                                                      // A CA certificate, but it cannot be used to sign other CA certificates,
                                                      // only end-entity certificates.
                                                      new BasicConstraints(0));

                certificateGenerator.AddExtension    (X509Extensions.KeyUsage,
                                                      critical: true,
                                                      new KeyUsage(
                                                          KeyUsage.DigitalSignature |
                                                          KeyUsage.KeyCertSign |
                                                          KeyUsage.CrlSign
                                                      ));

                serverCA_ECC_Certificate = certificateGenerator.Generate(new Asn1SignatureFactory(eccSignatureAlgorithm, rootCA_ECC_KeyPair.Private, secureRandom));

                using (var writer = new StreamWriter(serverCA_ECC_certificateFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(serverCA_ECC_Certificate);
                    pemWriter.Writer.Flush();
                }

            }

            if (serverCA_RSA_KeyPair       is null)
            {

                var rsaKeyPairGenerator = new RsaKeyPairGenerator();
                rsaKeyPairGenerator.Init(new KeyGenerationParameters(secureRandom, 4096));
                serverCA_RSA_KeyPair = rsaKeyPairGenerator.GenerateKeyPair();

                using (var writer = new StreamWriter(serverCA_RSA_privateKeyFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(serverCA_RSA_KeyPair.Private);
                    pemWriter.Writer.Flush();
                }

            }

            if (serverCA_RSA_Certificate   is null)
            {

                var certificateGenerator  = new X509V3CertificateGenerator();

                certificateGenerator.SetIssuerDN     (new X509Name(rootCA_RSA_Certificate.SubjectDN.ToString()));
                certificateGenerator.SetSubjectDN    (new X509Name("CN=Open Charging Cloud - Server CA (RSA), O=GraphDefined GmbH, OU=TestCA, L=Jena, C=Germany"));
                certificateGenerator.SetNotBefore    (Timestamp.Now.AddDays (-3).DateTime);
                certificateGenerator.SetNotAfter     (Timestamp.Now.AddYears(23).DateTime);
                certificateGenerator.SetPublicKey    (serverCA_RSA_KeyPair.Public);
                certificateGenerator.SetSerialNumber (BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));

                certificateGenerator.AddExtension    (X509Extensions.BasicConstraints,
                                                      critical: true,
                                                      // A CA certificate, but it cannot be used to sign other CA certificates,
                                                      // only end-entity certificates.
                                                      new BasicConstraints(0));

                certificateGenerator.AddExtension    (X509Extensions.KeyUsage,
                                                      critical: true,
                                                      new KeyUsage(
                                                          KeyUsage.DigitalSignature |
                                                          KeyUsage.KeyCertSign |
                                                          KeyUsage.CrlSign
                                                      ));

                serverCA_RSA_Certificate = certificateGenerator.Generate(new Asn1SignatureFactory(rsaSignatureAlgorithm, rootCA_RSA_KeyPair.Private, secureRandom));

                using (var writer = new StreamWriter(serverCA_RSA_certificateFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(serverCA_RSA_Certificate);
                    pemWriter.Writer.Flush();
                }

            }


            if (clientCA_ECC_KeyPair       is null)
            {

                var keyPairGenerator = new ECKeyPairGenerator();
                keyPairGenerator.Init(eccKeyGenParams);
                clientCA_ECC_KeyPair = keyPairGenerator.GenerateKeyPair();

                using (var writer = new StreamWriter(clientCA_ECC_privateKeyFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(clientCA_ECC_KeyPair.Private);
                    pemWriter.Writer.Flush();
                }

            }

            if (clientCA_ECC_Certificate   is null)
            {

                var certificateGenerator  = new X509V3CertificateGenerator();

                certificateGenerator.SetIssuerDN     (new X509Name(rootCA_ECC_Certificate.SubjectDN.ToString()));
                certificateGenerator.SetSubjectDN    (new X509Name("CN=Open Charging Cloud - Client CA (ECC), O=GraphDefined GmbH, OU=TestCA, L=Jena, C=Germany"));
                certificateGenerator.SetNotBefore    (Timestamp.Now.AddDays (-2).DateTime);
                certificateGenerator.SetNotAfter     (Timestamp.Now.AddYears(+5).DateTime);
                certificateGenerator.SetPublicKey    (clientCA_ECC_KeyPair.Public);
                certificateGenerator.SetSerialNumber (BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));

                certificateGenerator.AddExtension    (X509Extensions.BasicConstraints,
                                                      critical: true,
                                                      // A CA certificate, but it cannot be used to sign other CA certificates,
                                                      // only end-entity certificates.
                                                      new BasicConstraints(0));

                certificateGenerator.AddExtension    (X509Extensions.KeyUsage,
                                                      critical: true,
                                                      new KeyUsage(
                                                          KeyUsage.DigitalSignature |
                                                          KeyUsage.KeyCertSign |
                                                          KeyUsage.CrlSign
                                                      ));

                clientCA_ECC_Certificate = certificateGenerator.Generate(new Asn1SignatureFactory(eccSignatureAlgorithm, rootCA_ECC_KeyPair.Private, secureRandom));

                using (var writer = new StreamWriter(clientCA_ECC_certificateFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(clientCA_ECC_Certificate);
                    pemWriter.Writer.Flush();
                }

            }

            if (clientCA_RSA_KeyPair       is null)
            {

                var rsaKeyPairGenerator = new RsaKeyPairGenerator();
                rsaKeyPairGenerator.Init(new KeyGenerationParameters(secureRandom, 4096));
                clientCA_RSA_KeyPair = rsaKeyPairGenerator.GenerateKeyPair();

                using (var writer = new StreamWriter(clientCA_RSA_privateKeyFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(clientCA_RSA_KeyPair.Private);
                    pemWriter.Writer.Flush();
                }

            }

            if (clientCA_RSA_Certificate   is null)
            {

                var certificateGenerator  = new X509V3CertificateGenerator();

                certificateGenerator.SetIssuerDN     (new X509Name(rootCA_ECC_Certificate.SubjectDN.ToString()));
                certificateGenerator.SetSubjectDN    (new X509Name("CN=Open Charging Cloud - Client CA (RSA), O=GraphDefined GmbH, OU=TestCA, L=Jena, C=Germany"));
                certificateGenerator.SetNotBefore    (Timestamp.Now.AddDays (-3).DateTime);
                certificateGenerator.SetNotAfter     (Timestamp.Now.AddYears(23).DateTime);
                certificateGenerator.SetPublicKey    (clientCA_RSA_KeyPair.Public);
                certificateGenerator.SetSerialNumber (BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));

                certificateGenerator.AddExtension    (X509Extensions.BasicConstraints,
                                                      critical: true,
                                                      // A CA certificate, but it cannot be used to sign other CA certificates,
                                                      // only end-entity certificates.
                                                      new BasicConstraints(0));

                certificateGenerator.AddExtension    (X509Extensions.KeyUsage,
                                                      critical: true,
                                                      new KeyUsage(
                                                          KeyUsage.DigitalSignature |
                                                          KeyUsage.KeyCertSign |
                                                          KeyUsage.CrlSign
                                                      ));

                clientCA_RSA_Certificate = certificateGenerator.Generate(new Asn1SignatureFactory(rsaSignatureAlgorithm, rootCA_RSA_KeyPair.Private, secureRandom));

                using (var writer = new StreamWriter(clientCA_RSA_certificateFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(clientCA_RSA_Certificate);
                    pemWriter.Writer.Flush();
                }

            }


            if (firmwareCA_ECC_KeyPair     is null)
            {

                var keyPairGenerator = new ECKeyPairGenerator();
                keyPairGenerator.Init(eccKeyGenParams);
                firmwareCA_ECC_KeyPair = keyPairGenerator.GenerateKeyPair();

                using (var writer = new StreamWriter(firmwareCA_ECC_privateKeyFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(firmwareCA_ECC_KeyPair.Private);
                    pemWriter.Writer.Flush();
                }

            }

            if (firmwareCA_ECC_Certificate is null)
            {

                var certificateGenerator  = new X509V3CertificateGenerator();

                certificateGenerator.SetIssuerDN     (new X509Name(rootCA_ECC_Certificate.SubjectDN.ToString()));
                certificateGenerator.SetSubjectDN    (new X509Name("CN=Open Charging Cloud - Firmware Signing CA (ECC), O=GraphDefined GmbH, OU=TestCA, L=Jena, C=Germany"));
                certificateGenerator.SetNotBefore    (Timestamp.Now.AddDays (-2).DateTime);
                certificateGenerator.SetNotAfter     (Timestamp.Now.AddYears(+5).DateTime);
                certificateGenerator.SetPublicKey    (firmwareCA_ECC_KeyPair.Public);
                certificateGenerator.SetSerialNumber (BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));

                certificateGenerator.AddExtension    (X509Extensions.BasicConstraints,
                                                      critical: true,
                                                      // A CA certificate, but it cannot be used to sign other CA certificates,
                                                      // only end-entity certificates.
                                                      new BasicConstraints(0));

                certificateGenerator.AddExtension    (X509Extensions.KeyUsage,
                                                      critical: true,
                                                      new KeyUsage(
                                                          KeyUsage.DigitalSignature |
                                                          KeyUsage.KeyCertSign |
                                                          KeyUsage.CrlSign
                                                      ));

                firmwareCA_ECC_Certificate = certificateGenerator.Generate(new Asn1SignatureFactory(eccSignatureAlgorithm, rootCA_ECC_KeyPair.Private, secureRandom));

                using (var writer = new StreamWriter(firmwareCA_ECC_certificateFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(firmwareCA_ECC_Certificate);
                    pemWriter.Writer.Flush();
                }

            }

            if (firmwareCA_RSA_KeyPair     is null)
            {

                var rsaKeyPairGenerator = new RsaKeyPairGenerator();
                rsaKeyPairGenerator.Init(new KeyGenerationParameters(secureRandom, 4096));
                firmwareCA_RSA_KeyPair = rsaKeyPairGenerator.GenerateKeyPair();

                using (var writer = new StreamWriter(firmwareCA_RSA_privateKeyFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(firmwareCA_RSA_KeyPair.Private);
                    pemWriter.Writer.Flush();
                }

            }

            if (firmwareCA_RSA_Certificate is null)
            {

                var certificateGenerator  = new X509V3CertificateGenerator();

                certificateGenerator.SetIssuerDN     (new X509Name(rootCA_ECC_Certificate.SubjectDN.ToString()));
                certificateGenerator.SetSubjectDN    (new X509Name("CN=Open Charging Cloud - Firmware Signing CA (RSA), O=GraphDefined GmbH, OU=TestCA, L=Jena, C=Germany"));
                certificateGenerator.SetNotBefore    (Timestamp.Now.AddDays (-3).DateTime);
                certificateGenerator.SetNotAfter     (Timestamp.Now.AddYears(23).DateTime);
                certificateGenerator.SetPublicKey    (firmwareCA_RSA_KeyPair.Public);
                certificateGenerator.SetSerialNumber (BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));

                certificateGenerator.AddExtension    (X509Extensions.BasicConstraints,
                                                      critical: true,
                                                      // A CA certificate, but it cannot be used to sign other CA certificates,
                                                      // only end-entity certificates.
                                                      new BasicConstraints(0));

                certificateGenerator.AddExtension    (X509Extensions.KeyUsage,
                                                      critical: true,
                                                      new KeyUsage(
                                                          KeyUsage.DigitalSignature |
                                                          KeyUsage.KeyCertSign |
                                                          KeyUsage.CrlSign
                                                      ));

                firmwareCA_RSA_Certificate = certificateGenerator.Generate(new Asn1SignatureFactory(rsaSignatureAlgorithm, rootCA_RSA_KeyPair.Private, secureRandom));

                using (var writer = new StreamWriter(firmwareCA_RSA_certificateFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(firmwareCA_RSA_Certificate);
                    pemWriter.Writer.Flush();
                }

            }


            // -------------------------------------------


            if (server1_ECC_KeyPair        is null)
            {

                var keyPairGenerator = new ECKeyPairGenerator();
                keyPairGenerator.Init(eccKeyGenParams);
                server1_ECC_KeyPair = keyPairGenerator.GenerateKeyPair();

                using (var writer = new StreamWriter(server1_ECC_privateKeyFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(server1_ECC_KeyPair.Private);
                    pemWriter.Writer.Flush();
                }

            }

            if (server1_ECC_Certificate    is null)
            {

                var certificateGenerator  = new X509V3CertificateGenerator();

                certificateGenerator.SetIssuerDN     (new X509Name(serverCA_ECC_Certificate.SubjectDN.ToString()));
                certificateGenerator.SetSubjectDN    (new X509Name("CN=api1.charging.cloud, O=GraphDefined GmbH, OU=ECC, L=Jena, C=Germany"));
                certificateGenerator.SetNotBefore    (Timestamp.Now.AddDays  (-1).DateTime);
                certificateGenerator.SetNotAfter     (Timestamp.Now.AddMonths(+3).DateTime);
                certificateGenerator.SetPublicKey    (server1_ECC_KeyPair.Public);
                certificateGenerator.SetSerialNumber (BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));

                certificateGenerator.AddExtension    (X509Extensions.KeyUsage,         critical: true, new KeyUsage        (KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
                certificateGenerator.AddExtension    (X509Extensions.ExtendedKeyUsage, critical: true, new ExtendedKeyUsage(KeyPurposeID.id_kp_serverAuth));

                certificateGenerator.AddExtension    (X509Extensions.SubjectAlternativeName, critical: false, new GeneralNames([
                                                                                                                                   new (GeneralName.DnsName,   "api1.charging.cloud"),
                                                                                                                                   new (GeneralName.IPAddress, "127.0.0.1"),
                                                                                                                                   new (GeneralName.IPAddress, "172.23.144.1")
                                                                                                                               ]));

                server1_ECC_Certificate = certificateGenerator.Generate(new Asn1SignatureFactory(eccSignatureAlgorithm, serverCA_ECC_KeyPair.Private, secureRandom));

                using (var writer = new StreamWriter(server1_ECC_certificateFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(server1_ECC_Certificate);
                    pemWriter.Writer.Flush();
                }

            }

            if (server1_RSA_KeyPair        is null)
            {

                var rsaKeyPairGenerator = new RsaKeyPairGenerator();
                rsaKeyPairGenerator.Init(new KeyGenerationParameters(secureRandom, 2048));
                server1_RSA_KeyPair = rsaKeyPairGenerator.GenerateKeyPair();

                using (var writer = new StreamWriter(server1_RSA_privateKeyFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(server1_RSA_KeyPair.Private);
                    pemWriter.Writer.Flush();
                }

            }

            if (server1_RSA_Certificate    is null)
            {

                var certificateGenerator  = new X509V3CertificateGenerator();

                certificateGenerator.SetIssuerDN     (new X509Name(serverCA_RSA_Certificate.SubjectDN.ToString()));
                certificateGenerator.SetSubjectDN    (new X509Name("CN=api1.charging.cloud, O=GraphDefined GmbH, OU=RSA, L=Jena, C=Germany"));
                certificateGenerator.SetNotBefore    (Timestamp.Now.AddDays  (-1).DateTime);
                certificateGenerator.SetNotAfter     (Timestamp.Now.AddMonths(+3).DateTime);
                certificateGenerator.SetPublicKey    (server1_RSA_KeyPair.Public);
                certificateGenerator.SetSerialNumber (BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));

                certificateGenerator.AddExtension    (X509Extensions.KeyUsage,               critical: true,  new KeyUsage        (KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
                certificateGenerator.AddExtension    (X509Extensions.ExtendedKeyUsage,       critical: true,  new ExtendedKeyUsage(KeyPurposeID.id_kp_serverAuth));

                certificateGenerator.AddExtension    (X509Extensions.SubjectAlternativeName, critical: false, new GeneralNames([
                                                                                                                                   new (GeneralName.DnsName,   "api1.charging.cloud"),
                                                                                                                                   new (GeneralName.IPAddress, "127.0.0.1"),
                                                                                                                                   new (GeneralName.IPAddress, "172.23.144.1")
                                                                                                                               ]));

                server1_RSA_Certificate = certificateGenerator.Generate(new Asn1SignatureFactory(rsaSignatureAlgorithm, serverCA_RSA_KeyPair.Private, secureRandom));

                using (var writer = new StreamWriter(server1_RSA_certificateFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(server1_RSA_Certificate);
                    pemWriter.Writer.Flush();
                }

            }


            if (client1_ECC_KeyPair        is null)
            {

                var keyPairGenerator = new ECKeyPairGenerator();
                keyPairGenerator.Init(eccKeyGenParams);
                client1_ECC_KeyPair = keyPairGenerator.GenerateKeyPair();

                using (var writer = new StreamWriter(client1_ECC_privateKeyFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(client1_ECC_KeyPair.Private);
                    pemWriter.Writer.Flush();
                }

            }

            if (client1_ECC_Certificate    is null)
            {

                var certificateGenerator  = new X509V3CertificateGenerator();

                certificateGenerator.SetIssuerDN     (new X509Name(clientCA_ECC_Certificate.SubjectDN.ToString()));
                certificateGenerator.SetSubjectDN    (new X509Name("CN=client1, O=GraphDefined GmbH, OU=ECC, L=Jena, C=Germany"));
                certificateGenerator.SetNotBefore    (Timestamp.Now.AddDays  (-1).DateTime);
                certificateGenerator.SetNotAfter     (Timestamp.Now.AddMonths(+3).DateTime);
                certificateGenerator.SetPublicKey    (client1_ECC_KeyPair.Public);
                certificateGenerator.SetSerialNumber (BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));

                certificateGenerator.AddExtension    (X509Extensions.KeyUsage,         critical: true, new KeyUsage        (KeyUsage.NonRepudiation | KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
                certificateGenerator.AddExtension    (X509Extensions.ExtendedKeyUsage, critical: true, new ExtendedKeyUsage(KeyPurposeID.id_kp_clientAuth));

                client1_ECC_Certificate = certificateGenerator.Generate(new Asn1SignatureFactory(eccSignatureAlgorithm, clientCA_ECC_KeyPair.Private, secureRandom));

                using (var writer = new StreamWriter(client1_ECC_certificateFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(client1_ECC_Certificate);
                    pemWriter.Writer.Flush();
                }

            }

            if (client1_RSA_KeyPair        is null)
            {

                var rsaKeyPairGenerator = new RsaKeyPairGenerator();
                rsaKeyPairGenerator.Init(new KeyGenerationParameters(secureRandom, 2048));
                client1_RSA_KeyPair = rsaKeyPairGenerator.GenerateKeyPair();

                using (var writer = new StreamWriter(client1_RSA_privateKeyFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(client1_RSA_KeyPair.Private);
                    pemWriter.Writer.Flush();
                }

            }

            if (client1_RSA_Certificate    is null)
            {

                var certificateGenerator  = new X509V3CertificateGenerator();

                certificateGenerator.SetIssuerDN     (new X509Name(clientCA_RSA_Certificate.SubjectDN.ToString()));
                certificateGenerator.SetSubjectDN    (new X509Name("CN=client1, O=GraphDefined GmbH, OU=RSA, L=Jena, C=Germany"));
                certificateGenerator.SetNotBefore    (Timestamp.Now.AddDays  (-1).DateTime);
                certificateGenerator.SetNotAfter     (Timestamp.Now.AddMonths(+3).DateTime);
                certificateGenerator.SetPublicKey    (client1_RSA_KeyPair.Public);
                certificateGenerator.SetSerialNumber (BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), secureRandom));

                certificateGenerator.AddExtension    (X509Extensions.KeyUsage,         critical: true, new KeyUsage        (KeyUsage.NonRepudiation | KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
                certificateGenerator.AddExtension    (X509Extensions.ExtendedKeyUsage, critical: true, new ExtendedKeyUsage(KeyPurposeID.id_kp_clientAuth));

                client1_RSA_Certificate = certificateGenerator.Generate(new Asn1SignatureFactory(rsaSignatureAlgorithm, clientCA_RSA_KeyPair.Private, secureRandom));

                using (var writer = new StreamWriter(client1_RSA_certificateFile))
                {
                    var pemWriter = new PemWriter(writer);
                    pemWriter.WriteObject(client1_RSA_Certificate);
                    pemWriter.Writer.Flush();
                }

            }

            #endregion

            #region Setup OCPP v2.1 Local Controller

            var testLCv2_1 = new TestLocalControllerNode(

                                 Id:                      NetworkingNode_Id.Parse("OCPPv2.1-LocalController-01"),

                                 VendorName:              "GraphDefined GmbH",
                                 Model:                   "vLC",
                                 Description:             I18NString.Create(Languages.en, "Our first virtual local controller!"),
                                 SerialNumber:            "SN-LC0001",
                                 SoftwareVersion:         "v0.1",
                                 Modem:                   new OCPPv2_1.Modem(
                                                              ICCID:   "0001",
                                                              IMSI:    "1112"
                                                          ),
                                 DisableSendHeartbeats:   true,

                                 HTTPAPI_Port:            IPPort.Parse(9930),

                                 //HTTPBasicAuth:           new Tuple<String, String>("GDNN001", "1234"),
                                 DNSClient:               dnsClient

                             );

            #region 9920 - OCPP LocalController v2.1 without internal security, but maybe with external TLS termination

            testLCv2_1.AttachWebSocketServer(
                TCPPort:                         IPPort.Parse(9920),
                Description:                     I18NString.Create("OCPP LocalController v2.1 open for all"),
                RequireAuthentication:           false,
                DisableWebSocketPings:           false,
                WebSocketPingEvery:              TimeSpan.FromMinutes(1),
                //ClientCAKeyPair:             clientCA_RSA_KeyPair,
                //ClientCACertificate:         clientCA_RSA_Certificate,
                //SlowNetworkSimulationDelay:  TimeSpan.FromMilliseconds(10),
                AutoStart:                       true
            );

            #endregion

            #region 9921 - OCPP LocalController v2.1 without internal security, but maybe with external TLS termination

            testLCv2_1.AttachWebSocketServer(
                TCPPort:                         IPPort.Parse(9921),
                Description:                     I18NString.Create("OCPP LocalController v2.1 without internal security, but maybe with external TLS termination"),
                RequireAuthentication:           true,
                DisableWebSocketPings:           false,
                WebSocketPingEvery:              TimeSpan.FromMinutes(1),
                //ClientCAKeyPair:             clientCA_RSA_KeyPair,
                //ClientCACertificate:         clientCA_RSA_Certificate,
                //SlowNetworkSimulationDelay:  TimeSpan.FromMilliseconds(10),
                AutoStart:                       true
            );

            #endregion

            #region 9922 - OCPP LocalController v2.1 with internal TLS termination using a private ECC PKI

            // cat serverCA.cert rootCA.cert > caChain.cert
            // openssl s_client -connect 127.0.0.1:9922 -CAfile caChain.cert -showcerts
            // openssl ec   -in server1ECC.key  -pubout 2>/dev/null | openssl dgst -sha256
            // openssl x509 -in server1ECC.cert -pubkey -noout      | openssl dgst -sha256
            //
            // openssl pkcs12 -export -out server1ECC.pfx -inkey server1ECC.key -in server1ECC.cert -certfile caChain.cert
            // openssl pkcs12 -in server1ECC.pfx - nokeys - passin pass:
            //
            // openssl ecparam -name secp256r1 -genkey -out secp256r1key.pem
            // MSYS_NO_PATHCONV=1 openssl req -new -key secp256r1key.pem -out secp256r1req.pem -subj '/C=US/ST=YourState/L=YourCity/O=YourOrganization/CN=yourname'
            // openssl x509 -req -in secp256r1req.pem -CA serverCA.cert -CAkey serverCA.key -CAcreateserial -out secp256r1cert.pem -days 365 -sha256

            // https://stackoverflow.com/questions/72096812/loading-x509certificate2-from-pem-file-results-in-no-credentials-are-available
            // https://www.daimto.com/how-to-use-x509certificate2-with-pem-file/
            // The TLS layer on Windows requires that the private key be written to disk (in a particular way).
            // The PEM-based certificate loading doesn't do that, only PFX-loading does.
            // The easiest way to make the TLS layer happy is to do:
            //     cert = new X509Certificate2(cert.Export(X509ContentType.Pfx));
            // That is, export the cert+key to a PFX, then import it again immediately (to get the side effect of the key being (temporarily)
            // written to disk in a way that SChannel can find it). You shouldn't need to bother with changing the PFX load flags off of the defaults,
            // though some complicatedly constrained users might need to use MachineKeySet.
            testLCv2_1.AttachWebSocketServer(
                TCPPort:                     IPPort.Parse(9922),
                Description:                 I18NString.Create("OCPP LocalController v2.1 with internal TLS termination using a private ECC PKI"),
                RequireAuthentication:       true,
                ServerCertificateSelector:   () => //new System.Security.Cryptography.X509Certificates.X509Certificate2(server1ECC_pfx, "", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.PersistKeySet),
                                                   new System.Security.Cryptography.X509Certificates.X509Certificate2(
                                                       System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(
                                                           server1_ECC_certificateFile,
                                                           server1_ECC_privateKeyFile
                                                       ).Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx)
                                                   ),

                                                   /// Authentication failed because the platform does not support ephemeral keys.
                                                   //System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(
                                                   //    Path.Combine(AppContext.BaseDirectory, "pki", "secp256r1cert.pem"),
                                                   //    Path.Combine(AppContext.BaseDirectory, "pki", "secp256r1key.pem")
                                                   //),
                DisableWebSocketPings:       false,

                //SlowNetworkSimulationDelay:  TimeSpan.FromMilliseconds(10),
                AutoStart:                   true
            );

            #endregion

            #region 9923 - OCPP LocalController v2.1 with internal TLS termination using a private RSA PKI

            // cat serverCA_RSA.cert rootCA_RSA.cert > caChain_RSA.cert
            // openssl s_client -connect 127.0.0.1:9923 -CAfile caChain_RSA.cert -showcerts
            // CONNECTED(00000160)
            // Can't use SSL_get_servername
            // depth=2 CN = Open Charging Cloud - Root CA, O = GraphDefined GmbH, L = Jena, C = Germany
            // verify return:1
            // depth=1 CN = Open Charging Cloud - Server CA, O = GraphDefined GmbH, L = Jena, C = Germany
            // verify return:1
            // depth=0 CN = api1.charging.cloud, O = GraphDefined GmbH, L = Jena, C = Germany
            // verify return:1
            // ---
            // Certificate chain
            //  0 s:CN = api1.charging.cloud, O = GraphDefined GmbH, L = Jena, C = Germany
            //    i:CN = Open Charging Cloud - Server CA, O = GraphDefined GmbH, L = Jena, C = Germany
            //    a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
            //    v:NotBefore: Mar  2 00:34:59 2024 GMT; NotAfter: Jun  3 00:34:59 2024 GMT
            testLCv2_1.AttachWebSocketServer(
                TCPPort:                     IPPort.Parse(9923),
                Description:                 I18NString.Create("OCPP LocalController v2.1 with internal TLS termination using a private RSA PKI"),
                RequireAuthentication:       true,
                ServerCertificateSelector:   () => ToDotNet(server1_RSA_Certificate, server1_RSA_KeyPair.Private)!,
                                                   //NotWorking:  System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(server1RSA_certificateFile, server1RSA_privateKeyFile),
                                                   //NotWorking:  ConvertToX509Certificate2(server1RSA_Certificate, server1RSA_KeyPair.Private),
                                                   //IsWorking:   new System.Security.Cryptography.X509Certificates.X509Certificate2(server1RSA_pfx, "", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.PersistKeySet),
                AllowedTLSProtocols:         System.Security.Authentication.SslProtocols.Tls12,

                DisableWebSocketPings:       false,
                //SlowNetworkSimulationDelay:  TimeSpan.FromMilliseconds(10),
                AutoStart:                   true
            );

            #endregion

            #region 9924 - OCPP LocalController v2.1 with internal TLS termination using a private RSA PKI enforcing TLS client authentication

            // Show client certificate details: openssl.exe x509 -in client1RSA.cert -text -noout
            //
            // cat serverCA_RSA.cert clientCA_RSA.cert rootCA_RSA.cert > caChain_RSA.cert
            // openssl s_client -connect 127.0.0.1:9923 -cert client1_RSA.cert -key client1_RSA.key -CAfile caChain_RSA.cert -showcerts
            testLCv2_1.AttachWebSocketServer(

                TCPPort:                      IPPort.Parse(9924),
                Description:                  I18NString.Create("OCPP LocalController v2.1 with internal TLS termination using a private RSA PKI enforcing TLS client authentication"),
                RequireAuthentication:        true,
                ServerCertificateSelector:    () => ToDotNet(server1_RSA_Certificate, server1_RSA_KeyPair.Private)!,
                                                    //NotWorking:  System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(server1RSA_certificateFile, server1RSA_privateKeyFile),
                                                    //NotWorking:  ConvertToX509Certificate2(server1RSA_Certificate, server1RSA_KeyPair.Private),
                                                    //IsWorking:   new System.Security.Cryptography.X509Certificates.X509Certificate2(server1RSA_pfx, "", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.PersistKeySet),
                AllowedTLSProtocols:          System.Security.Authentication.SslProtocols.Tls12 |
                                              System.Security.Authentication.SslProtocols.Tls13,

                ClientCertificateRequired:    true,
                ClientCertificateValidator:   (sender,
                                               certificate,
                                               certificateChain,
                                               webSocketServer,
                                               policyErrors) => {

                                                   if (certificate      is not null &&
                                                       certificateChain is not null)
                                                   {

                                                       if (webSocketServer.TrustedClientCertificates.Contains(certificate))
                                                           return TLSValidationResult.Success();

                                                       return TLSValidationResult.Failed("Could not validate the received TLS client certificate!");

                                                   }

                                                   return TLSValidationResult.Failed("Missing or invalid TLS client certificate!");

                                               },

                LocalCertificateSelector:     (sender,
                                               targetHost,
                                               localCertificates,
                                               remoteCertificate,
                                               acceptableIssuers) => {
                                                   return localCertificates.First();
                                               },

                DisableWebSocketPings:        false,
                //SlowNetworkSimulationDelay:  TimeSpan.FromMilliseconds(10),
                AutoStart:                    true

            );

            #endregion


            #region HowTo test using Win11 + WSL

            // Win11:
            //  - Import RootCA to "Trusted Root Certification Authorities" for the entire computer
            //  - Import ServerCA to "Intermediate Certification Authorities" for the entire computer
            //  - Verify via "certmgr"

            // Win11 WSL (Debian):
            //  - sudo wget -qO /usr/local/bin/websocat https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl
            //  - chmod +x /usr/local/bin/websocat
            //
            // Note: The IPv4 address of your host (here: 172.23.144.1) might be different!

            // $ websocat --protocol ocpp2.1 --basic-auth a:b -v ws://172.23.144.1:9920
            // [INFO  websocat::lints] Auto-inserting the line mode
            // [INFO  websocat::stdio_threaded_peer] get_stdio_peer (threaded)
            // [INFO  websocat::ws_client_peer] get_ws_client_peer
            // [INFO  websocat::ws_client_peer] Connected to ws
            //
            // Paste the following line:
            // [2,"100000","BootNotification",{"chargingStation":{"model":"aa","vendorName":"bb"},"reason":"ApplicationReset"}]
            //
            // [3,"100000",{"status":"Rejected","currentTime":"2024-03-03T11:46:59.076Z","interval":30}]
            // [INFO  websocat::ws_peer] Received WebSocket ping

            // $ cat serverCA_RSA.cert rootCA_RSA.cert > caChain_RSA.cert
            // $ export SSL_CERT_FILE=/home/ahzf/OCPPTests/caChain_RSA.cert
            // $ websocat --protocol ocpp2.1 --basic-auth a:b -v wss://172.23.144.1:9922
            // [INFO  websocat::lints] Auto-inserting the line mode
            // [INFO  websocat::stdio_threaded_peer] get_stdio_peer (threaded)
            // [INFO  websocat::ws_client_peer] get_ws_client_peer
            // [INFO  websocat::ws_client_peer] Connected to ws
            //
            // Paste the following line:
            // [2,"100000","BootNotification",{"chargingStation":{"model":"aa","vendorName":"bb"},"reason":"ApplicationReset"}]
            //
            // [3,"100000",{"status":"Rejected","currentTime":"2024-03-03T11:43:54.364Z","interval":30}]
            // [INFO  websocat::ws_peer] Received WebSocket ping

            #endregion





            //var ocppWebSocketServer23 = testLCv2_1.AttachWebAPI(
            //                                HTTPServerPort:                  IPPort.Parse(9203),
            //                                RequireAuthentication:           true,
            //                                AutoStart:                       true
            //                            );


            //      var webSocketServerV2_1        = testCSMSv2_1.CSMSServers.First() as WebSocketServer;

            //testCSMSv2_1.AddOrUpdateHTTPBasicAuth(SourceRouting.To("CP001"), "dummy-dev-password");


            #region HTTP Web Socket connections

            testLCv2_1.OnNewWebSocketTCPConnection            += async (timestamp, server, connection, eventTrackingId, ct) => {

                await DebugLog(
                    $"New TCP connection from {connection.RemoteSocket}",
                    ct
                );

                await WriteToLogfileV2_1(
                    $"{timestamp.ToISO8601()}\tNEW TCP\t-\t{connection.RemoteSocket}",
                    ct
                );

            };

            testLCv2_1.OnNewWebSocketServerConnection         += async (timestamp, server, connection, sharedSubprotocols, eventTrackingId, ct) => {

                await DebugLog(
                    $"New HTTP WebSocket connection from '{connection.Login}' ({connection.RemoteSocket}) using '{sharedSubprotocols.AggregateWith(", ")}'",
                    ct
                );

                await WriteToLogfileV2_1(
                    $"{timestamp.ToISO8601()}\tNEW WS\t{connection.Login}\t{connection.RemoteSocket}",
                    ct
                );

            };

            testLCv2_1.OnWebSocketServerCloseMessageReceived  += async (timestamp, server, connection, frame, eventTrackingId, statusCode, reason, ct) => {

                await DebugLog(
                    $"'{connection.Login}' wants to close its HTTP WebSocket connection ({connection.RemoteSocket}): {statusCode}{(reason is not null ? $", '{reason}'" : "")}",
                    ct
                );

                await WriteToLogfileV2_1(
                    $"{timestamp.ToISO8601()}\tCLOSE\t{connection.Login}\t{connection.RemoteSocket}",
                    ct
                );

            };

            testLCv2_1.OnWebSocketServerTCPConnectionClosed   += async (timestamp, server, connection, eventTrackingId, reason, ct) => {

                await DebugLog(
                    $"'{connection.Login}' closed its HTTP WebSocket connection ({connection.RemoteSocket}){(reason is not null ? $": '{reason}'" : "")}",
                    ct
                );

                await WriteToLogfileV2_1(
                    $"{timestamp.ToISO8601()}\tCLOSED\t{connection.Login}\t{connection.RemoteSocket}",
                    ct
                );

            };

            #endregion

            #region HTTP Web Socket Pings/Pongs

            //(testCSMSv2_1.CSMSServers.First() as WebSocketServer).OnPingMessageReceived += async (timestamp, server, connection, eventTrackingId, frame) => {
            //    DebugX.Log(nameof(WebSocketServer) + ": Ping received: '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargingStationId") + ", " + connection.RemoteSocket + ")");
            //    lock (testCSMSv2_1)
            //    {
            //        File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
            //                           String.Concat(timestamp.ToISO8601(), "\tPING IN\t", connection.TryGetCustomData("chargingStationId"), "\t", connection.RemoteSocket, Environment.NewLine));
            //    }
            //};

            //(testCSMSv2_1.CSMSServers.First() as WebSocketServer).OnPingMessageSent += async (timestamp, server, connection, eventTrackingId, frame) => {
            //    DebugX.Log(nameof(WebSocketServer) + ": Ping sent:     '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargingStationId") + ", " + connection.RemoteSocket + ")");
            //    lock (testCSMSv2_1)
            //    {
            //        File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
            //                           String.Concat(timestamp.ToISO8601(), "\tPING OUT\t", connection.TryGetCustomData("chargingStationId"), "\t", connection.RemoteSocket, Environment.NewLine));
            //    }
            //};

            //(testCSMSv2_1.CSMSServers.First() as WebSocketServer).OnPongMessageReceived += async (timestamp, server, connection, eventTrackingId, frame) => {
            //    DebugX.Log(nameof(WebSocketServer) + ": Pong received: '" + frame.Payload.ToUTF8String() + "' (" + connection.TryGetCustomData("chargingStationId") + ", " + connection.RemoteSocket + ")");
            //    lock (testCSMSv2_1)
            //    {
            //        File.AppendAllText(Path.Combine(AppContext.BaseDirectory, "TextMessages.log"),
            //                           String.Concat(timestamp.ToISO8601(), "\tPONG IN\t", connection.TryGetCustomData("chargingStationId"), "\t", connection.RemoteSocket, Environment.NewLine));
            //    }
            //};

            #endregion

            #region JSON Messages

            testLCv2_1.OCPP.IN.OnJSONRequestMessageReceived  += async (timestamp, server, connection, jsonRequestMessage, ct) => {

                await DebugLog(
                    $"Received a JSON web socket request from '{jsonRequestMessage.NetworkPath.Source}': '{jsonRequestMessage.Payload.ToString(Formatting.None)}'!",
                    ct
                );

                await WriteToLogfileV2_1(
                    // RemoteSocket???
                    $"{jsonRequestMessage.RequestTimestamp.ToISO8601()}\tREQ IN\t{jsonRequestMessage.NetworkPath.Source}\t{jsonRequestMessage.NetworkPath.Source}\t{jsonRequestMessage.Payload.ToString(Formatting.None)}",
                    ct
                );

            };

            testLCv2_1.OCPP.IN.OnJSONResponseMessageReceived     += async (timestamp, server, connection, jsonResponseMessage, ct) => {

                await DebugLog(
                    $"Received a JSON web socket response from '{jsonResponseMessage.NetworkPath.Source}': '{jsonResponseMessage.Payload.ToString(Formatting.None)}'!",
                    ct
                );

                await WriteToLogfileV2_1(
                    $"{jsonResponseMessage.ResponseTimestamp.ToISO8601()}\tRES IN\t{jsonResponseMessage.NetworkPath.Source}\t{jsonResponseMessage.NetworkPath.Source}\t{jsonResponseMessage.Payload.ToString(Formatting.None)}",
                    ct
                );

            };

            testLCv2_1.OCPP.IN.OnJSONRequestErrorMessageReceived   += async (timestamp, server, connection, jsonRequestErrorMessage,  ct) => {
                await Task.Delay(1, ct);
            };

            testLCv2_1.OCPP.IN.OnJSONResponseErrorMessageReceived  += async (timestamp, server, connection, jsonResponseErrorMessage, ct) => {
                await Task.Delay(1, ct);
            };

            testLCv2_1.OCPP.IN.OnJSONSendMessageReceived           += async (timestamp, server, connection, jsonSendMessage,          ct) => {
                await Task.Delay(1, ct);
            };



            testLCv2_1.OCPP.OUT.OnJSONRequestMessageSent        += async (timestamp, server, connection, jsonRequestMessage, sentMessageResult, ct) => {

                await DebugLog(
                    $"Sent a JSON web socket request to '{jsonRequestMessage.Destination.Last}': '{jsonRequestMessage.Payload.ToString(Formatting.None)}'!",
                    ct
                );

                await WriteToLogfileV2_1(
                    $"{jsonRequestMessage.RequestTimestamp.ToISO8601()}\tREQ OUT\t{jsonRequestMessage.Destination.Last}\t{jsonRequestMessage.Destination.Last}\t{jsonRequestMessage.Payload.ToString(Formatting.None)}",
                    ct
                );

            };

            testLCv2_1.OCPP.OUT.OnJSONResponseMessageSent      += async (timestamp, server, connection, jsonResponseMessage, sentMessageResult, ct) => {

                await DebugLog(
                    $"Sent a JSON web socket response to '{jsonResponseMessage.Destination.Last}': '{jsonResponseMessage.Payload.ToString(Formatting.None)}'!",
                    jsonResponseMessage.CancellationToken
                );

                await WriteToLogfileV2_1(
                    // RemoteSocket???
                    $"{jsonResponseMessage.ResponseTimestamp.ToISO8601()}\tRES OUT\t{jsonResponseMessage.Destination.Last}\t{jsonResponseMessage.Destination.Last}\t{jsonResponseMessage.Payload.ToString(Formatting.None)}",
                    jsonResponseMessage.CancellationToken
                );

            };

            testLCv2_1.OCPP.OUT.OnJSONRequestErrorMessageSent   += async (timestamp, server, connection, jsonRequestErrorMessage,  sentMessageResult, ct) => {
                await Task.Delay(1, ct);
            };

            testLCv2_1.OCPP.OUT.OnJSONResponseErrorMessageSent  += async (timestamp, server, connection, jsonResponseErrorMessage, sentMessageResult, ct) => {
                await Task.Delay(1, ct);
            };

            testLCv2_1.OCPP.OUT.OnJSONSendMessageSent           += async (timestamp, server, connection, jsonSendMessage,          sentMessageResult, ct) => {
                await Task.Delay(1, ct);
            };

            #endregion

            #region Binary Messages

            //testLCv2_1.OCPP.IN.OnBinaryMessageRequestReceived   += async (timestamp,
            //                                                              server,
            //                                                              binaryRequestMessage) => {

            //                                                                  await DebugLog(
            //        $"Received a binary web socket request from '{binaryRequestMessage.NetworkPath.Source}': '{binaryRequestMessage.Payload.ToBase64()}'!",
            //        binaryRequestMessage.CancellationToken
            //    );

            //    await WriteToLogfileV2_1(
            //        $"{binaryRequestMessage.RequestTimestamp.ToISO8601()}\tREQ IN\t{binaryRequestMessage.DestinationId}\t{binaryRequestMessage.DestinationId}\t{binaryRequestMessage.Payload.ToBase64()}",
            //        binaryRequestMessage.CancellationToken
            //    );

            //};

            //testLCv2_1.OCPP.OUT.OnBinaryMessageResponseSent     += async (timestamp,
            //                                                              server,
            //                                                              binaryResponseMessage) => {

            //    await DebugLog(
            //        $"Sent a binary web socket response to '{binaryResponseMessage.DestinationId}': '{binaryResponseMessage.Payload.ToBase64()}'!",
            //        binaryResponseMessage.CancellationToken
            //    );

            //    await WriteToLogfileV2_1(
            //        $"{binaryResponseMessage.ResponseTimestamp.ToISO8601()}\tRES OUT\t{binaryResponseMessage.DestinationId}\t{binaryResponseMessage.DestinationId}\t{binaryResponseMessage.Payload.ToBase64()}",
            //        binaryResponseMessage.CancellationToken
            //    );

            //};

            //testLCv2_1.OCPP.OUT.OnBinaryMessageRequestSent      += async (timestamp,
            //                                                              server,
            //                                                              binaryRequestMessage) => {

            //                                                                  await DebugLog(
            //        $"Sent a binary web socket request to '{binaryRequestMessage.DestinationId}': '{binaryRequestMessage.Payload.ToBase64()}'!",
            //        binaryRequestMessage.CancellationToken
            //    );

            //    await WriteToLogfileV2_1(
            //        $"{binaryRequestMessage.RequestTimestamp.ToISO8601()}\tREQ OUT\t{binaryRequestMessage.DestinationId}\t{binaryRequestMessage.DestinationId}\t{binaryRequestMessage.Payload.ToBase64()}",
            //        binaryRequestMessage.CancellationToken
            //    );

            //};

            //testLCv2_1.OCPP.IN.OnBinaryMessageResponseReceived  += async (timestamp,
            //                                                              server,
            //                                                              binaryResponseMessage) => {

            //                                                                  await DebugLog(
            //        $"Received a binary web socket response from '{binaryResponseMessage.NetworkPath.Source}': '{binaryResponseMessage.Payload.ToBase64()}'!",
            //        binaryResponseMessage.CancellationToken
            //    );

            //    await WriteToLogfileV2_1(
            //        $"{binaryResponseMessage.ResponseTimestamp.ToISO8601()}\tRES IN\t{binaryResponseMessage.NetworkPath.Source}\t{binaryResponseMessage.NetworkPath.Source}\t{binaryResponseMessage.Payload.ToBase64()}",
            //        binaryResponseMessage.CancellationToken
            //    );

            //};

            #endregion

            // ERRORS!!!

            #endregion


            testLCv2_1.AddOrUpdateHTTPBasicAuth(NetworkingNode_Id.Parse("GD001"), "1234");


            DebugX.Log();
            DebugX.Log("Startup finished...");

            #region Wait for key 'Q' pressed... and quit.

            #region Data

            String[]?  commandArray        = null;
            //var        ocppVersion         = "v2.1";
            var        chargingStationId   = NetworkingNode_Id.Zero;
            var        quit                = false;

            #endregion

            do
            {

                try
                {

                    commandArray = Console.ReadLine()?.Trim()?.Split(' ');

                    if (commandArray is not null &&
                        commandArray.Length != 0)
                    {

                        var command = commandArray[0]?.ToLower();

                        if (command is not null &&
                            command.Length > 0)
                        {

                            if (command == "q")
                                quit = true;

                            #region Use {chargingStationId}

                            if (command.Equals("use", StringComparison.OrdinalIgnoreCase) && commandArray.Length == 2)
                            {
                                if (NetworkingNode_Id.TryParse(commandArray[1], out var newChargingStationId))
                                {
                                    chargingStationId = newChargingStationId;
                                    DebugX.Log($"Now using charging station '{chargingStationId}'!");
                                }
                                else
                                    DebugX.Log($"Invalid charging station identification: '{commandArray[1]}'!");
                            }

                            #endregion

                            #region AddHTTPBasicAuth

                            //   AddHTTPBasicAuth abcd1234
                            if (command.Equals("addHTTPBasicAuth", StringComparison.OrdinalIgnoreCase) && commandArray.Length == 2)
                            {
                           //     testLCv2_1.         AddOrUpdateHTTPBasicAuth(SourceRouting.To(chargingStationId), commandArray[2]);
                            }

                            #endregion


                            if (chargingStationId == NetworkingNode_Id.Zero)
                                DebugX.Log("No charging station selected!");

                            else
                            {

                                #region Reset

                                //   Reset ...
                                if (command.Equals("reset", StringComparison.OrdinalIgnoreCase) && commandArray.Length == 2)
                                {

                                    var resetType = commandArray[1].ToLower();

                                    var response = await testLCv2_1.OCPP.OUT.Reset(
                                                       new OCPPv2_1.CSMS.ResetRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           ResetType:     resetType switch {
                                                                              "immediate"  => OCPPv2_1.ResetType.Immediate,
                                                                              "onidle"     => OCPPv2_1.ResetType.OnIdle,
                                                                              _            => throw new CommandException("reset Immediate|OnIdle")
                                                                          }
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }


                                //   Reset {EVSEId} ...
                                if (command.Equals("reset", StringComparison.OrdinalIgnoreCase) && commandArray.Length == 3)
                                {

                                    var resetType = commandArray[2].ToLower();

                                    var response = await testLCv2_1.OCPP.OUT.Reset(
                                                       new OCPPv2_1.CSMS.ResetRequest(
                                                           Destination:    SourceRouting.To(chargingStationId),
                                                           ResetType:           resetType switch {
                                                                                    "immediate"  => OCPPv2_1.ResetType.Immediate,
                                                                                    "onidle"     => OCPPv2_1.ResetType.OnIdle,
                                                                                    _            => throw new CommandException("reset {EVSEId} Immediate|OnIdle")
                                                                                },
                                                           EVSEId:              OCPPv2_1.EVSE_Id.Parse(commandArray[1])
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region UpdateFirmware

                                //   UpdateFirmware https://api2.ocpp.charging.cloud:9901/firmware.bin
                                if (command.Equals("UpdateFirmware", StringComparison.OrdinalIgnoreCase) && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.UpdateFirmware(
                                                       new OCPPv2_1.CSMS.UpdateFirmwareRequest(
                                                            Destination:          SourceRouting.To(chargingStationId),
                                                            Firmware:                  new OCPPv2_1.Firmware(
                                                                                           FirmwareURL:          URL.Parse(commandArray[1]),
                                                                                           RetrieveTimestamp:    Timestamp.Now,
                                                                                           InstallTimestamp:     Timestamp.Now,
                                                                                           SigningCertificate:   "xxx",
                                                                                           Signature:            "yyy"
                                                                                       ),
                                                            UpdateFirmwareRequestId:   RandomExtensions.RandomInt32(),
                                                            Retries:                   3,
                                                            RetryInterval:             null
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                // PublishFirmware

                                // UnpublishFirmware

                                #region GetBaseReport

                                //   GetBaseReport conf
                                //   GetBaseReport full
                                if (command.Equals("GetBaseReport", StringComparison.OrdinalIgnoreCase) && (commandArray.Length == 1 || commandArray.Length == 2))
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetBaseReport(
                                                       new OCPPv2_1.CSMS.GetBaseReportRequest(
                                                           Destination:         SourceRouting.To(chargingStationId),
                                                           GetBaseReportRequestId:   RandomExtensions.RandomInt32(),
                                                           ReportBase:               commandArray[1] switch {
                                                                                         "conf"  => OCPPv2_1.ReportBase.ConfigurationInventory,
                                                                                         "full"  => OCPPv2_1.ReportBase.FullInventory,
                                                                                         _       => OCPPv2_1.ReportBase.SummaryInventory
                                                                                     }
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region GetReport

                                //   GetReport OCPPCommCtrlr
                                if (command.Equals("GetReport", StringComparison.OrdinalIgnoreCase) && (commandArray.Length == 2 || commandArray.Length == 3))
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetReport(
                                                       new OCPPv2_1.CSMS.GetReportRequest(
                                                           Destination:     SourceRouting.To(chargingStationId),
                                                           GetReportRequestId:   RandomExtensions.RandomInt32(),
                                                           //ComponentCriteria:    new[] {
                                                           //                          OCPPv2_1.ComponentCriteria.Active
                                                           //                      },
                                                           ComponentVariables:   [
                                                                                     new OCPPv2_1.ComponentVariable(
                                                                                         Component:   new OCPPv2_1.Component(
                                                                                                          Name:       commandArray[1],
                                                                                                          Instance:   null,
                                                                                                          EVSE:       null
                                                                                                      )
                                                                                         //Variable:    new OCPPv2_1.Variable(
                                                                                         //                 Name:       "",
                                                                                         //                 Instance:   null
                                                                                         //             )
                                                                                     )
                                                                                 ]

                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region GetLog

                                if (command.Equals("GetLog", StringComparison.OrdinalIgnoreCase) && commandArray.Length == 3)
                                {

                                    //   getlog http://172.20.101.28:9921 security
                                    //   getlog https://api2.ocpp.charging.cloud:9901 diagnostics
                                    //   getlog https://api2.ocpp.charging.cloud:9901 security
                                    //   getlog https://api2.ocpp.charging.cloud:9901 datacollector
                                    var response = await testLCv2_1.OCPP.OUT.GetLog(
                                                       new OCPPv2_1.CSMS.GetLogRequest(
                                                           Destination:      SourceRouting.To(chargingStationId),
                                                           LogType:         commandArray[2].ToLower() switch {
                                                                                 "security"       => OCPPv2_1.LogType.SecurityLog,
                                                                                 "datacollector"  => OCPPv2_1.LogType.DataCollectorLog,
                                                                                 _                => OCPPv2_1.LogType.DiagnosticsLog
                                                                            },
                                                           LogRequestId:    1,
                                                           Log:             new OCPPv2_1.LogParameters(
                                                                                RemoteLocation:    URL.Parse(commandArray[1]),
                                                                                OldestTimestamp:   null,
                                                                                LatestTimestamp:   null
                                                                            ),
                                                           Retries:         null,
                                                           RetryInterval:   null
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region SetVariables

                                //   SetVariables component variable value
                                if (command == "SetVariables".ToLower() && commandArray.Length == 4)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.SetVariables(
                                                       new OCPPv2_1.CSMS.SetVariablesRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           VariableData:       [
                                                                                   new OCPPv2_1.SetVariableData(
                                                                                       new OCPPv2_1.Component(
                                                                                           Name:       commandArray[1],
                                                                                           Instance:   null,
                                                                                           EVSE:       null
                                                                                       ),
                                                                                       new OCPPv2_1.Variable(
                                                                                           Name:       commandArray[2],
                                                                                           Instance:   null
                                                                                       ),
                                                                                       commandArray[3]
                                                                                       //OCPPv2_1.AttributeTypes.Actual
                                                                                   )
                                                                               ]
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region GetVariables

                                //   GetVariables component variable
                                if (command == "GetVariables".ToLower() && commandArray.Length == 3)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetVariables(
                                                       new OCPPv2_1.CSMS.GetVariablesRequest(
                                                           Destination:     SourceRouting.To(chargingStationId),
                                                           VariableData:   [
                                                                               new OCPPv2_1.GetVariableData(
                                                                                   new OCPPv2_1.Component(
                                                                                       Name:       commandArray[1],
                                                                                       Instance:   null,
                                                                                       EVSE:       null
                                                                                   ),
                                                                                   new OCPPv2_1.Variable(
                                                                                       Name:       commandArray[2],
                                                                                       Instance:   null
                                                                                   )
                                                                               )
                                                                           ]
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region SetMonitoringBase

                                //   SetMonitoringBase
                                //   SetMonitoringBase factory
                                //   SetMonitoringBase hard
                                if (command == "SetMonitoringBase".ToLower() && (commandArray.Length == 1 || commandArray.Length == 2))
                                {

                                    var response = await testLCv2_1.OCPP.OUT.SetMonitoringBase(
                                                       new OCPPv2_1.CSMS.SetMonitoringBaseRequest(
                                                           Destination: SourceRouting.To(chargingStationId),
                                                           MonitoringBase:   commandArray[1] switch {
                                                                                 "factory"  => OCPPv2_1.MonitoringBase.FactoryDefault,
                                                                                 "hard"     => OCPPv2_1.MonitoringBase.HardWiredOnly,
                                                                                 _          => OCPPv2_1.MonitoringBase.All
                                                                             }
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region GetMonitoringReport

                                //   GetMonitoringReport component [variable]
                                if (command == "GetMonitoringReport".ToLower() && (commandArray.Length == 2 || commandArray.Length == 3))
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetMonitoringReport(
                                                       new OCPPv2_1.CSMS.GetMonitoringReportRequest(
                                                           Destination:               SourceRouting.To(chargingStationId),
                                                           GetMonitoringReportRequestId:   RandomExtensions.RandomInt32(),
                                                           MonitoringCriteria:             [
                                                                                               OCPPv2_1.MonitoringCriterion.PeriodicMonitoring
                                                                                           ],
                                                           ComponentVariables:             [
                                                                                               new OCPPv2_1.ComponentVariable(
                                                                                                   new OCPPv2_1.Component(
                                                                                                       Name:       commandArray[1],
                                                                                                       Instance:   null,
                                                                                                       EVSE:       null
                                                                                                   ),
                                                                                                   commandArray.Length == 3
                                                                                                       ? new OCPPv2_1.Variable(
                                                                                                             Name:       commandArray[2],
                                                                                                             Instance:   null
                                                                                                         )
                                                                                                       : null
                                                                                               )
                                                                                           ]
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region SetMonitoringLevel

                                //   SetMonitoringLevel debug
                                //   SetMonitoringLevel informational
                                //   SetMonitoringLevel notice
                                //   SetMonitoringLevel warning
                                //   SetMonitoringLevel alert
                                //   SetMonitoringLevel critical
                                //   SetMonitoringLevel systemfailure
                                //   SetMonitoringLevel hardwarefailure
                                //   SetMonitoringLevel danger
                                if (command == "SetMonitoringLevel".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.SetMonitoringLevel(
                                                       new OCPPv2_1.CSMS.SetMonitoringLevelRequest(
                                                           Destination:    SourceRouting.To(chargingStationId),
                                                           Severity:      commandArray[1].ToLower() switch {
                                                                              "danger"           => OCPPv2_1.Severities.Danger,
                                                                              "hardwarefailure"  => OCPPv2_1.Severities.HardwareFailure,
                                                                              "systemfailure"    => OCPPv2_1.Severities.SystemFailure,
                                                                              "critical"         => OCPPv2_1.Severities.Critical,
                                                                              "alert"            => OCPPv2_1.Severities.Alert,
                                                                              "warning"          => OCPPv2_1.Severities.Warning,
                                                                              "notice"           => OCPPv2_1.Severities.Notice,
                                                                              "informational"    => OCPPv2_1.Severities.Informational,
                                                                              "debug"            => OCPPv2_1.Severities.Debug,
                                                                              _                  => OCPPv2_1.Severities.Error
                                                                          }
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region ClearVariableMonitoring

                                //   ClearVariableMonitoring 1
                                if (command == "ClearVariableMonitoring".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.ClearVariableMonitoring(
                                                       new OCPPv2_1.CSMS.ClearVariableMonitoringRequest(
                                                           Destination:        SourceRouting.To(chargingStationId),
                                                           VariableMonitoringIds:   [
                                                                                        OCPPv2_1.VariableMonitoring_Id.Parse(commandArray[1])
                                                                                    ]
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                // SetNetworkProfile

                                #region Change Availability

                                //   ChangeAvailability operative
                                //   ChangeAvailability inoperative
                                if (command == "ChangeAvailability".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.ChangeAvailability(
                                                       new OCPPv2_1.CSMS.ChangeAvailabilityRequest(
                                                           Destination:    SourceRouting.To(chargingStationId),
                                                           OperationalStatus:   commandArray[1].ToLower() switch {
                                                                                    "operative"  => OCPPv2_1.OperationalStatus.Operative,
                                                                                    _            => OCPPv2_1.OperationalStatus.Inoperative
                                                                                }
                                                       )
                                                   );


                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }



                                //   ChangeAvailability 1 operative
                                //   ChangeAvailability 1 inoperative
                                if (command == "ChangeAvailability".ToLower() && commandArray.Length == 3)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.ChangeAvailability(
                                                       new OCPPv2_1.CSMS.ChangeAvailabilityRequest(
                                                           Destination:    SourceRouting.To(chargingStationId),
                                                           OperationalStatus:   commandArray[2].ToLower() switch {
                                                                                    "operative"  => OCPPv2_1.OperationalStatus.Operative,
                                                                                    _            => OCPPv2_1.OperationalStatus.Inoperative
                                                                                },
                                                           EVSE:                new OCPPv2_1.EVSE(
                                                                                    Id:  OCPPv2_1.EVSE_Id.Parse(commandArray[1])
                                                                                )
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }



                                //   ChangeAvailability 1 1 operative
                                //   ChangeAvailability 1 1 inoperative
                                if (command == "ChangeAvailability".ToLower() && commandArray.Length == 4)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.ChangeAvailability(
                                                       new OCPPv2_1.CSMS.ChangeAvailabilityRequest(
                                                           Destination:    SourceRouting.To(chargingStationId),
                                                           OperationalStatus:   commandArray[3].ToLower() switch {
                                                                                    "operative"  => OCPPv2_1.OperationalStatus.Operative,
                                                                                    _            => OCPPv2_1.OperationalStatus.Inoperative
                                                                                },
                                                           EVSE:                new OCPPv2_1.EVSE(
                                                                                    Id:            OCPPv2_1.EVSE_Id.     Parse(commandArray[1]),
                                                                                    ConnectorId:   OCPPv2_1.Connector_Id.Parse(commandArray[2])
                                                                                )
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region Trigger Message

                                //   TriggerMessage BootNotification
                                //   TriggerMessage LogStatusNotification
                                //   TriggerMessage DiagnosticsStatusNotification
                                //   TriggerMessage FirmwareStatusNotification
                                //   TriggerMessage Heartbeat
                                //   TriggerMessage MeterValues
                                //   TriggerMessage SignChargePointCertificate
                                if (command == "TriggerMessage".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.TriggerMessage(
                                                       new OCPPv2_1.CSMS.TriggerMessageRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           RequestedMessage:   commandArray[1].ToLower() switch {
                                                                                   "bootnotification"                => OCPPv2_1.MessageTrigger.BootNotification,
                                                                                   "logstatusnotification"           => OCPPv2_1.MessageTrigger.LogStatusNotification,
                                                                                   "diagnosticsstatusnotification"   => OCPPv2_1.MessageTrigger.DiagnosticsStatusNotification,
                                                                                   "firmwarestatusnotification"      => OCPPv2_1.MessageTrigger.FirmwareStatusNotification,
                                                                                   "metervalues"                     => OCPPv2_1.MessageTrigger.MeterValues,
                                                                                   "SignChargingStationCertificate"  => OCPPv2_1.MessageTrigger.SignChargingStationCertificate,
                                                                                   "statusnotification"              => OCPPv2_1.MessageTrigger.StatusNotification,
                                                                                   _                                 => OCPPv2_1.MessageTrigger.Heartbeat
                                                                               }
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }



                                //   TriggerMessage 1 BootNotification
                                //   TriggerMessage 1 LogStatusNotification
                                //   TriggerMessage 1 DiagnosticsStatusNotification
                                //   TriggerMessage 1 FirmwareStatusNotification
                                //   TriggerMessage 1 Heartbeat
                                //   TriggerMessage 1 MeterValues
                                //   TriggerMessage 1 SignChargePointCertificate
                                if (command == "TriggerMessage".ToLower() && commandArray.Length == 3)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.TriggerMessage(
                                                       new OCPPv2_1.CSMS.TriggerMessageRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           RequestedMessage:   commandArray[2].ToLower() switch {
                                                                                   "bootnotification"                => OCPPv2_1.MessageTrigger.BootNotification,
                                                                                   "logstatusnotification"           => OCPPv2_1.MessageTrigger.LogStatusNotification,
                                                                                   "diagnosticsstatusnotification"   => OCPPv2_1.MessageTrigger.DiagnosticsStatusNotification,
                                                                                   "firmwarestatusnotification"      => OCPPv2_1.MessageTrigger.FirmwareStatusNotification,
                                                                                   "metervalues"                     => OCPPv2_1.MessageTrigger.MeterValues,
                                                                                   "SignChargingStationCertificate"  => OCPPv2_1.MessageTrigger.SignChargingStationCertificate,
                                                                                   "statusnotification"              => OCPPv2_1.MessageTrigger.StatusNotification,
                                                                                   _                                 => OCPPv2_1.MessageTrigger.Heartbeat
                                                                               },
                                                           EVSE:               new OCPPv2_1.EVSE(
                                                                                   OCPPv2_1.EVSE_Id.Parse(commandArray[1])
                                                                               )
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }


                                //   TriggerMessage 1 1 StatusNotification
                                if (command == "TriggerMessage".ToLower() && commandArray.Length == 4)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.TriggerMessage(
                                                       new OCPPv2_1.CSMS.TriggerMessageRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           RequestedMessage:   commandArray[3].ToLower() switch {
                                                                                   "bootnotification"                => OCPPv2_1.MessageTrigger.BootNotification,
                                                                                   "logstatusnotification"           => OCPPv2_1.MessageTrigger.LogStatusNotification,
                                                                                   "diagnosticsstatusnotification"   => OCPPv2_1.MessageTrigger.DiagnosticsStatusNotification,
                                                                                   "firmwarestatusnotification"      => OCPPv2_1.MessageTrigger.FirmwareStatusNotification,
                                                                                   "metervalues"                     => OCPPv2_1.MessageTrigger.MeterValues,
                                                                                   "SignChargingStationCertificate"  => OCPPv2_1.MessageTrigger.SignChargingStationCertificate,
                                                                                   "statusnotification"              => OCPPv2_1.MessageTrigger.StatusNotification,
                                                                                   _                                 => OCPPv2_1.MessageTrigger.Heartbeat
                                                                               },
                                                           EVSE:               new OCPPv2_1.EVSE(
                                                                                   OCPPv2_1.EVSE_Id.     Parse(commandArray[1]),
                                                                                   OCPPv2_1.Connector_Id.Parse(commandArray[2])
                                                                               )
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region Update Firmware

                                //   UpdateFirmware http://95.89.178.27:9901/firmware.bin
                                if (command == "UpdateFirmware".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.UpdateFirmware(
                                                       new OCPPv2_1.CSMS.UpdateFirmwareRequest(
                                                           Destination:          SourceRouting.To(chargingStationId),
                                                           Firmware:                  new OCPPv2_1.Firmware(
                                                                                          FirmwareURL:          URL.Parse(commandArray[1]),
                                                                                          RetrieveTimestamp:    Timestamp.Now,
                                                                                          InstallTimestamp:     Timestamp.Now + TimeSpan.FromMinutes(1),
                                                                                          SigningCertificate:   "-----BEGIN CERTIFICATE-----\n" +
                                                                                                                "MIICFzCCAZwCFCqVyLDfPQJywMwU7pwXbiUREPH/MAoGCCqGSM49BAMDMGoxCzAJ\n" +
                                                                                                                "BgNVBAYTAk5MMRIwEAYDVQQIDAlGbGV2b2xhbmQxDzANBgNVBAcMBkFsbWVyZTET\n" +
                                                                                                                "MBEGA1UECgwKQWxmZW4gTi5WLjEMMAoGA1UECwwDQUNFMRMwEQYDVQQDDApBSFdQ\n" +
                                                                                                                "MDEtREVWMCAXDTIyMDIwODEzMTEzNFoYDzIwNjQwMjA4MTMxMTM0WjByMQswCQYD\n" +
                                                                                                                "VQQGEwJOTDESMBAGA1UECAwJRmxldm9sYW5kMQ8wDQYDVQQHDAZBbG1lcmUxEzAR\n" +
                                                                                                                "BgNVBAoMCkFsZmVuIE4uVi4xDDAKBgNVBAsMA0FDRTEbMBkGA1UEAwwSQUhXUC1E\n" +
                                                                                                                "RVYtRGV2ZWxvcGVyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEdjJ42sfXY7af4BaT\n" +
                                                                                                                "2SU69RUtl5Wudb/wj/X8t19HYkQdqMg7R93AN6+K8x1ZGb+YWRLsPWt/EtYhmvAc\n" +
                                                                                                                "77Hjbu/ufori4IBs5qgQGa9na/alvexSG0qShRs79FUZIKcFMAoGCCqGSM49BAMD\n" +
                                                                                                                "A2kAMGYCMQDWOw4qFA1NFfVspD3NkL7D8fSppDmQAWAn+KFdqhs/1rhP1ldt822C\n" +
                                                                                                                "eEzEBzdUfp0CMQCzFmVQbAuxwn9sMoiB7GSpaMa2ayT0WJcgoLSaFFet2sf2ZlJy\n" +
                                                                                                                "9nHH2QCphACm184=\n" +
                                                                                                                "-----END CERTIFICATE-----\n",
                                                                                          Signature:            "3066023100f3e4beaa47d963d90051233603f59ade779aacd7d8939bcf41b5dc7a9cf139b433d859dfb6d4fbb885d32b225da6fa42023100cc10f35ba4440a69b1789bed7a3031eb30f5cdf2ce8ea2e9070968eaa862ad9e6fb334652184e46925a0df79355b74e8"
                                                                                      ),
                                                           UpdateFirmwareRequestId:   RandomExtensions.RandomInt32(),
                                                           Retries:                   3,
                                                           RetryInterval:             TimeSpan.FromSeconds(10)
                                                       )
                                                   );;

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region Transfer Data

                                //   TransferData graphdefined
                                if (command == "transferdata".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.DataTransfer(
                                                       new OCPPv2_1.DataTransferRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           VendorId:      cloud.charging.open.protocols.WWCP.Vendor_Id.Parse(commandArray[1])
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }




                                //   TransferData graphdefined message
                                if (command == "transferdata".ToLower() && (commandArray.Length == 2 || commandArray.Length == 3))
                                {

                                    var response = await testLCv2_1.OCPP.OUT.DataTransfer(
                                                       new OCPPv2_1.DataTransferRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           VendorId:      cloud.charging.open.protocols.WWCP.Vendor_Id.Parse(commandArray[1]),
                                                           MessageId:     commandArray.Length == 3 ? OCPPv2_1.Message_Id.Parse(commandArray[2]) : null
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }




                                //   TransferData graphdefined message data
                                if (command == "transferdata".ToLower() && commandArray.Length == 4)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.DataTransfer(
                                                       new OCPPv2_1.DataTransferRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           VendorId:      cloud.charging.open.protocols.WWCP.Vendor_Id. Parse(commandArray[1]),
                                                           MessageId:     OCPPv2_1.Message_Id.Parse(commandArray[2]),
                                                           Data:          commandArray[3]
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion


                                #region SendSignedCertificate

                                //   SendSignedCertificate $Filename v2g|csc
                                if (command == "SendSignedCertificate".ToLower() && commandArray.Length == 3)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.CertificateSigned(
                                                       new OCPPv2_1.CSMS.CertificateSignedRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           CertificateChain:   OCPPv2_1.CertificateChain.Parse(
                                                                                   File.ReadAllText(commandArray[1])
                                                                               ),
                                                           CertificateType:    commandArray[2].ToLower() switch {
                                                                                   "v2g"  => OCPPv2_1.CertificateSigningUse.V2GCertificate,
                                                                                   _      => OCPPv2_1.CertificateSigningUse.ChargingStationCertificate
                                                                               }
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region InstallCertificate

                                if (command == "InstallCertificate".ToLower() && commandArray.Length == 3)
                                {

                                    //   InstallCertificate $FileName oem|mo|csms|manu|v2g
                                    var response = await testLCv2_1.OCPP.OUT.InstallCertificate(
                                                       new OCPPv2_1.CSMS.InstallCertificateRequest(
                                                           Destination:  SourceRouting.To(chargingStationId),
                                                           CertificateType:   commandArray[2].ToLower() switch {
                                                                                  "oem"   => OCPPv2_1.InstallCertificateUse.OEMRootCertificate,
                                                                                  "mo"    => OCPPv2_1.InstallCertificateUse.MORootCertificate,
                                                                                  "csms"  => OCPPv2_1.InstallCertificateUse.CSMSRootCertificate,
                                                                                  "manu"  => OCPPv2_1.InstallCertificateUse.ManufacturerRootCertificate,
                                                                                  _       => OCPPv2_1.InstallCertificateUse.V2GRootCertificate
                                                           },
                                                           Certificate:       OCPPv2_1.Certificate.Parse(
                                                                                  File.ReadAllText(commandArray[1])
                                                                              )
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region GetInstalledCertificateIds

                                if (command == "GetInstalledCertificateIds".ToLower() && commandArray.Length == 2)
                                {

                                    //   GetInstalledCertificateIds v2grc
                                    //   GetInstalledCertificateIds morc
                                    //   GetInstalledCertificateIds csrc
                                    //   GetInstalledCertificateIds v2gcc
                                    var response = await testLCv2_1.OCPP.OUT.GetInstalledCertificateIds(
                                                       new OCPPv2_1.CSMS.GetInstalledCertificateIdsRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           CertificateTypes:   [
                                                                                   commandArray[1].ToLower() switch {
                                                                                       "v2g"   => OCPPv2_1.GetCertificateIdUse.V2GRootCertificate,
                                                                                       "mo"    => OCPPv2_1.GetCertificateIdUse.MORootCertificate,
                                                                                       "csms"  => OCPPv2_1.GetCertificateIdUse.CSMSRootCertificate,
                                                                                       "manu"  => OCPPv2_1.GetCertificateIdUse.ManufacturerRootCertificate,
                                                                                       "oem"   => OCPPv2_1.GetCertificateIdUse.OEMRootCertificate,
                                                                                       _       => OCPPv2_1.GetCertificateIdUse.V2GCertificateChain
                                                                                   }
                                                                               ]
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region DeleteCertificate

                                //   DeleteCertificate $HashAlgorithm $IssuerNameHash $IssuerPublicKeyHash $SerialNumber
                                if (command == "DeleteCertificate".ToLower() && commandArray.Length == 5)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.DeleteCertificate(
                                                       new OCPPv2_1.CSMS.DeleteCertificateRequest(
                                                           Destination:      SourceRouting.To(chargingStationId),
                                                           CertificateHashData:   new OCPPv2_1.CertificateHashData(
                                                                                      commandArray[1].ToLower() switch {
                                                                                          "sha512"  => OCPPv2_1.HashAlgorithms.SHA512,
                                                                                          "sha384"  => OCPPv2_1.HashAlgorithms.SHA384,
                                                                                          _         => OCPPv2_1.HashAlgorithms.SHA256
                                                                                      },
                                                                                      commandArray[2],
                                                                                      commandArray[3],
                                                                                      commandArray[4]
                                                                                  )
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                // NotifyCRLAvailability


                                #region GetLocalListVersion

                                //   GetLocalListVersion
                                if (command == "GetLocalListVersion".ToLower() && commandArray.Length == 1)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetLocalListVersion(
                                                       new OCPPv2_1.CSMS.GetLocalListVersionRequest(
                                                           SourceRouting.To(chargingStationId)
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region SendLocalList

                                //   SendLocalList
                                if (command == "SendLocalList".ToLower() && commandArray.Length == 1)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.SendLocalList(
                                                       new OCPPv2_1.CSMS.SendLocalListRequest(
                                                       SourceRouting.To(chargingStationId),
                                                             1, // 0 is not allowed!
                                                             OCPPv2_1.UpdateTypes.Full,
                                                             [
                                                                 //new OCPPv2_1.AuthorizationData(OCPPv2_1.IdToken.Parse("046938f2fc6880"), new OCPPv2_1.IdTagInfo(OCPPv2_1.AuthorizationStatus.Blocked)),
                                                                 //new OCPPv2_1.AuthorizationData(OCPPv2_1.IdToken.Parse("aabbcc11"),       new OCPPv2_1.IdTagInfo(OCPPv2_1.AuthorizationStatus.Accepted)),
                                                                 //new OCPPv2_1.AuthorizationData(OCPPv2_1.IdToken.Parse("aabbcc22"),       new OCPPv2_1.IdTagInfo(OCPPv2_1.AuthorizationStatus.Accepted)),
                                                                 //new OCPPv2_1.AuthorizationData(OCPPv2_1.IdToken.Parse("aabbcc33"),       new OCPPv2_1.IdTagInfo(OCPPv2_1.AuthorizationStatus.Accepted)),
                                                                 new OCPPv2_1.AuthorizationData(
                                                                     new OCPPv2_1.IdToken(
                                                                         Value:   "cabot",
                                                                         Type:    OCPPv2_1.IdTokenType.ISO14443
                                                                     ),
                                                                     new OCPPv2_1.IdTokenInfo(
                                                                         OCPPv2_1.AuthorizationStatus.Accepted
                                                                     )
                                                                 )
                                                             ]
                                                         )
                                                     );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region ClearCache

                                //   clearcache GD002
                                if (command == "clearcache"             && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.ClearCache(
                                                       new OCPPv2_1.CSMS.ClearCacheRequest(
                                                           SourceRouting.To(chargingStationId)
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion


                                #region ReserveNow

                                //   ReserveNow 1 $ReservationId aabbccdd
                                if (command == "ReserveNow".ToLower() && commandArray.Length == 4)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.ReserveNow(
                                                       new OCPPv2_1.CSMS.ReserveNowRequest(
                                                           Destination:     SourceRouting.To(chargingStationId),
                                                           Id:              OCPPv2_1.Reservation_Id.Parse(commandArray[2]),
                                                           ExpiryDate:      Timestamp.Now + TimeSpan.FromMinutes(15),
                                                           IdToken:         new OCPPv2_1.IdToken(
                                                                                Value:             commandArray[3],
                                                                                Type:              OCPPv2_1.IdTokenType.eMAID,
                                                                                AdditionalInfos:   null
                                                                            ),
                                                           ConnectorType:   null, //OCPPv2_1.ConnectorTypes.sType2,
                                                           EVSEId:          OCPPv2_1.EVSE_Id.       Parse(commandArray[1]),
                                                           GroupIdToken:    null
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region Cancel Reservation

                                //   CancelReservation $ReservationId
                                if (command == "CancelReservation".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.CancelReservation(
                                                       new OCPPv2_1.CSMS.CancelReservationRequest(
                                                           Destination:  SourceRouting.To(chargingStationId),
                                                           ReservationId:     OCPPv2_1.Reservation_Id.   Parse(commandArray[1])
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region Remote Start Transaction

                                //   RemoteStart 1 $IdToken
                                if (command == "remotestart".ToLower() && commandArray.Length == 3)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.RequestStartTransaction(
                                                       new OCPPv2_1.CSMS.RequestStartTransactionRequest(
                                                           Destination:                   SourceRouting.To(chargingStationId),
                                                           RequestStartTransactionRequestId:   OCPPv2_1.RemoteStart_Id.NewRandom,
                                                           IdToken:                            new OCPPv2_1.IdToken(
                                                                                                   Value:             commandArray[2],
                                                                                                   Type:              OCPPv2_1.IdTokenType.ISO14443,
                                                                                                   AdditionalInfos:   null
                                                                                               ),
                                                           EVSEId:                             OCPPv2_1.EVSE_Id.Parse(commandArray[1]),
                                                           ChargingProfile:                    null,
                                                           GroupIdToken:                       null
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region Remote Stop Transaction

                                //   RemoteStop $TransactionId
                                if (command == "RemoteStop".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.RequestStopTransaction(
                                                       new OCPPv2_1.CSMS.RequestStopTransactionRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           TransactionId:      OCPPv2_1.Transaction_Id.    Parse(commandArray[1])
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region GetTransactionStatus

                                //   GetTransactionStatus
                                if (command == "GetTransactionStatus".ToLower() && commandArray.Length == 1)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetTransactionStatus(
                                                       new OCPPv2_1.CSMS.GetTransactionStatusRequest(
                                                           Destination:    SourceRouting.To(chargingStationId)
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }



                                //   GetTransactionStatus $TransactionId
                                if (command == "GetTransactionStatus".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetTransactionStatus(
                                                       new OCPPv2_1.CSMS.GetTransactionStatusRequest(
                                                           Destination:    SourceRouting.To(chargingStationId),
                                                           TransactionId:       OCPPv2_1.Transaction_Id.    Parse(commandArray[1])
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region SetChargingProfile

                                //   setprofile1 1
                                if (command == "setprofile1"            && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.SetChargingProfile(
                                                       new OCPPv2_1.CSMS.SetChargingProfileRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           EVSEId:             OCPPv2_1.EVSE_Id.     Parse(commandArray[1]),
                                                           ChargingProfile:    new OCPPv2_1.ChargingProfile(
                                                                                   OCPPv2_1.ChargingProfile_Id.Parse("100"),
                                                                                   0,
                                                                                   OCPPv2_1.ChargingProfilePurpose.TxDefaultProfile,
                                                                                   OCPPv2_1.ChargingProfileKinds.Recurring,
                                                                                   [
                                                                                       new OCPPv2_1.ChargingSchedule(
                                                                                           Id:                       OCPPv2_1.ChargingSchedule_Id.Parse("1"),
                                                                                           ChargingRateUnit:         OCPPv2_1.ChargingRateUnits.Amperes,
                                                                                           ChargingSchedulePeriods:  [
                                                                                                                         new OCPPv2_1.ChargingSchedulePeriod(
                                                                                                                             StartPeriod:     TimeSpan.FromHours(0),  // == 00:00 Uhr
                                                                                                                             Limit:           OCPPv2_1.ChargingRateValue.Parse(16, OCPPv2_1.ChargingRateUnits.Amperes),
                                                                                                                             NumberOfPhases:  3
                                                                                                                         ),
                                                                                                                         new OCPPv2_1.ChargingSchedulePeriod(
                                                                                                                             StartPeriod:     TimeSpan.FromHours(8),  // == 08:00 Uhr
                                                                                                                             Limit:           OCPPv2_1.ChargingRateValue.Parse(6,  OCPPv2_1.ChargingRateUnits.Amperes),
                                                                                                                             NumberOfPhases:  3
                                                                                                                         ),
                                                                                                                         new OCPPv2_1.ChargingSchedulePeriod(
                                                                                                                             StartPeriod:     TimeSpan.FromHours(20), // == 20:00 Uhr
                                                                                                                             Limit:           OCPPv2_1.ChargingRateValue.Parse(12, OCPPv2_1.ChargingRateUnits.Amperes),
                                                                                                                             NumberOfPhases:  3
                                                                                                                         )
                                                                                                                     ],
                                                                                           Duration:                 TimeSpan.FromDays(7),
                                                                                           StartSchedule:            DateTime.Parse("2023-03-29T00:00:00Z").ToUniversalTime()
                                                                                       )
                                                                                   ],
                                                                                   null, //Transaction_Id.TryParse(5678),
                                                                                   OCPPv2_1.RecurrencyKinds.Daily,
                                                                                   DateTime.Parse("2022-11-01T00:00:00Z").ToUniversalTime(),
                                                                                   DateTime.Parse("2023-12-01T00:00:00Z").ToUniversalTime()
                                                                               )
                                                           )
                                                       );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                //   setprofile2 GD002 1
                                if (command == "setprofile2"            && commandArray.Length == 3)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.SetChargingProfile(
                                                       new OCPPv2_1.CSMS.SetChargingProfileRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           EVSEId:             OCPPv2_1.EVSE_Id.     Parse(commandArray[2]),
                                                           ChargingProfile:    new OCPPv2_1.ChargingProfile(
                                                                                   OCPPv2_1.ChargingProfile_Id.Parse("100"),
                                                                                   2,
                                                                                   OCPPv2_1.ChargingProfilePurpose.TxDefaultProfile,
                                                                                   OCPPv2_1.ChargingProfileKinds.Recurring,
                                                                                   [
                                                                                       new OCPPv2_1.ChargingSchedule(
                                                                                           Id:                       OCPPv2_1.ChargingSchedule_Id.Parse("1"),
                                                                                           ChargingRateUnit:         OCPPv2_1.ChargingRateUnits.Amperes,
                                                                                           ChargingSchedulePeriods:  [
                                                                                                                         new OCPPv2_1.ChargingSchedulePeriod(
                                                                                                                             StartPeriod:     TimeSpan.FromHours(0),  // == 00:00 Uhr
                                                                                                                             Limit:           OCPPv2_1.ChargingRateValue.Parse(11, OCPPv2_1.ChargingRateUnits.Amperes),
                                                                                                                             NumberOfPhases:  3
                                                                                                                         ),
                                                                                                                         new OCPPv2_1.ChargingSchedulePeriod(
                                                                                                                             StartPeriod:     TimeSpan.FromHours(6),  // == 06:00 Uhr
                                                                                                                             Limit:           OCPPv2_1.ChargingRateValue.Parse(6,  OCPPv2_1.ChargingRateUnits.Amperes),
                                                                                                                             NumberOfPhases:  3
                                                                                                                         ),
                                                                                                                         new OCPPv2_1.ChargingSchedulePeriod(
                                                                                                                             StartPeriod:     TimeSpan.FromHours(21), // == 21:00 Uhr
                                                                                                                             Limit:           OCPPv2_1.ChargingRateValue.Parse(11, OCPPv2_1.ChargingRateUnits.Amperes),
                                                                                                                             NumberOfPhases:  3
                                                                                                                         )
                                                                                                                     ],
                                                                                           Duration:                 TimeSpan.FromDays(7),
                                                                                           StartSchedule:            DateTime.Parse("2023-03-29T00:00:00Z").ToUniversalTime()
                                                                                       )
                                                                                   ],
                                                                                   null, //Transaction_Id.TryParse(6789),
                                                                                   OCPPv2_1.RecurrencyKinds.Daily,
                                                                                   DateTime.Parse("2022-11-01T00:00:00Z").ToUniversalTime(),
                                                                                   DateTime.Parse("2023-12-01T00:00:00Z").ToUniversalTime()
                                                                               )
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region GetChargingProfiles

                                //   GetChargingProfiles
                                if (command == "GetChargingProfiles".ToLower() && commandArray.Length == 1)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetChargingProfiles(
                                                       new OCPPv2_1.CSMS.GetChargingProfilesRequest(
                                                           Destination:               SourceRouting.To(chargingStationId),
                                                           GetChargingProfilesRequestId:   RandomExtensions.RandomInt32(),
                                                           ChargingProfile:                new OCPPv2_1.ChargingProfileCriterion(
                                                                                               ChargingProfilePurpose:   OCPPv2_1.ChargingProfilePurpose.TxDefaultProfile,
                                                                                               StackLevel:               null,
                                                                                               ChargingProfileIds:       null,
                                                                                               ChargingLimitSources:     null
                                                                                           ),
                                                           EVSEId:                         null
                                                       )
                                                   );;

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }



                                //   GetChargingProfiles $ChargingProfileId
                                if (command == "GetChargingProfiles".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetChargingProfiles(
                                                       new OCPPv2_1.CSMS.GetChargingProfilesRequest(
                                                           Destination:               SourceRouting.To(chargingStationId),
                                                           GetChargingProfilesRequestId:   RandomExtensions.RandomInt32(),
                                                           ChargingProfile:                new OCPPv2_1.ChargingProfileCriterion(
                                                                                               ChargingProfilePurpose:   null,
                                                                                               StackLevel:               null,
                                                                                               ChargingProfileIds:       [
                                                                                                                             OCPPv2_1.ChargingProfile_Id.Parse(commandArray[1])
                                                                                                                         ],
                                                                                               ChargingLimitSources:     null
                                                                                           ),
                                                           EVSEId:                         null
                                                       )
                                                   );;

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region ClearChargingProfile

                                //   ClearChargingProfile
                                if (command == "ClearChargingProfile".ToLower() && commandArray.Length == 1)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.ClearChargingProfile(
                                                       new OCPPv2_1.CSMS.ClearChargingProfileRequest(
                                                           Destination:   SourceRouting.To(chargingStationId)
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }



                                //   ClearChargingProfile $ChargingProfileId
                                if (command == "ClearChargingProfile".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.ClearChargingProfile(
                                                       new OCPPv2_1.CSMS.ClearChargingProfileRequest(
                                                           Destination:    SourceRouting.To(chargingStationId),
                                                           ChargingProfileId:   OCPPv2_1.ChargingProfile_Id.Parse(commandArray[1])
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }



                                //   ClearChargingProfile $ConnectorId/EVSEId $ChargingProfileId
                                if (command == "ClearChargingProfile".ToLower() && commandArray.Length == 3)
                                {

                                    //   ClearChargingProfile $EVSEId $ChargingProfileId
                                    var response = await testLCv2_1.OCPP.OUT.ClearChargingProfile(
                                                       new OCPPv2_1.CSMS.ClearChargingProfileRequest(
                                                           Destination:          SourceRouting.To(chargingStationId),
                                                           ChargingProfileId:         OCPPv2_1.ChargingProfile_Id.Parse(commandArray[2]),
                                                           ChargingProfileCriteria:   new OCPPv2_1.ClearChargingProfile(
                                                                                          EVSEId:                   OCPPv2_1.EVSE_Id.Parse(commandArray[1]),
                                                                                          ChargingProfilePurpose:   null,
                                                                                          StackLevel:               null
                                                                                      )
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region GetCompositeSchedule

                                //   GetCompositeSchedule 1 3600
                                if (command == "GetCompositeSchedule".ToLower() && commandArray.Length == 3)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetCompositeSchedule(
                                                       new OCPPv2_1.CSMS.GetCompositeScheduleRequest(
                                                           Destination:   SourceRouting.To(chargingStationId),
                                                           Duration:           TimeSpan.FromSeconds(UInt32.Parse(commandArray[2])),
                                                           EVSEId:             OCPPv2_1.EVSE_Id.Parse(commandArray[1]),
                                                           ChargingRateUnit:   null
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                // UpdateDynamicSchedule

                                // NotifyAllowedenergyTransfer

                                // UsePriorityCharging

                                #region Unlock Connector

                                //   UnlockConnector 1 1
                                if (command == "UnlockConnector".ToLower() && commandArray.Length == 3)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.UnlockConnector(
                                                       new OCPPv2_1.CSMS.UnlockConnectorRequest(
                                                           Destination:    SourceRouting.To(chargingStationId),
                                                           EVSEId:        OCPPv2_1.EVSE_Id.     Parse(commandArray[1]),
                                                           ConnectorId:   OCPPv2_1.Connector_Id.Parse(commandArray[2])
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion


                                // SendAFDRSignal


                                #region SetDisplayMessage

                                //   SetDisplayMessage test123
                                if (command == "SetDisplayMessage".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.SetDisplayMessage(
                                                       new OCPPv2_1.CSMS.SetDisplayMessageRequest(
                                                           Destination:    SourceRouting.To(chargingStationId),
                                                           Message:             new OCPPv2_1.MessageInfo(
                                                                                    Id:               OCPPv2_1.DisplayMessage_Id.NewRandom,
                                                                                    Priority:         OCPPv2_1.MessagePriority.NormalCycle,
                                                                                    Message:          new OCPPv2_1.MessageContent(
                                                                                                          Content:      commandArray[1],
                                                                                                          Language:     OCPPv2_1.Language_Id.EN,
                                                                                                          Format:       OCPPv2_1.MessageFormat.UTF8,
                                                                                                          CustomData:   null
                                                                                                      ),
                                                                                    State:            OCPPv2_1.MessageState.Idle,
                                                                                    StartTimestamp:   Timestamp.Now,
                                                                                    EndTimestamp:     Timestamp.Now + TimeSpan.FromHours(1),
                                                                                    TransactionId:    null,
                                                                                    Display:          null
                                                                                )
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region GetDisplayMessages

                                //   GetDisplayMessages
                                if (command == "GetDisplayMessages".ToLower() && commandArray.Length == 1)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetDisplayMessages(
                                                       new OCPPv2_1.CSMS.GetDisplayMessagesRequest(
                                                           Destination:              SourceRouting.To(chargingStationId),
                                                           GetDisplayMessagesRequestId:   RandomExtensions.RandomInt32(),
                                                           Ids:                           null,
                                                           Priority:                      null,
                                                           State:                         null
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }



                                //   GetDisplayMessages 1
                                if (command == "GetDisplayMessages".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetDisplayMessages(
                                                       new OCPPv2_1.CSMS.GetDisplayMessagesRequest(
                                                           Destination:              SourceRouting.To(chargingStationId),
                                                           GetDisplayMessagesRequestId:   RandomExtensions.RandomInt32(),
                                                           Ids:                           [
                                                                                              OCPPv2_1.DisplayMessage_Id.Parse(commandArray[1])
                                                                                          ],
                                                           Priority:                      null,
                                                           State:                         null
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }



                                //   GetDisplayMessagesByState Idle
                                if (command == "GetDisplayMessagesByState".ToLower() && commandArray.Length == 2)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.GetDisplayMessages(
                                                       new OCPPv2_1.CSMS.GetDisplayMessagesRequest(
                                                           Destination:              SourceRouting.To(chargingStationId),
                                                           GetDisplayMessagesRequestId:   RandomExtensions.RandomInt32(),
                                                           Ids:                           null,
                                                           Priority:                      null,
                                                           State:                         OCPPv2_1.MessageState.Parse(commandArray[1].ToLower())
                                                                                             // charging
                                                                                             // faulted
                                                                                             // idle
                                                                                             // unavailable
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }
                                #endregion

                                #region SendCostUpdated

                                //   SendCostUpdate 123.45 ABCDEFG
                                if (command == "SendCostUpdate".ToLower() && commandArray.Length == 3)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.CostUpdated(
                                                       new OCPPv2_1.CSMS.CostUpdatedRequest(
                                                           Destination:    SourceRouting.To(chargingStationId),
                                                           TotalCost:           Decimal.                    Parse(commandArray[1]),
                                                           TransactionId:       OCPPv2_1.Transaction_Id.    Parse(commandArray[2])
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                                #region RequestCustomerInformation

                                //   RequestCustomerInformation $RFIDId
                                if (command == "RequestCustomerInformation".ToLower() && commandArray.Length == 1)
                                {

                                    var response = await testLCv2_1.OCPP.OUT.CustomerInformation(
                                                       new OCPPv2_1.CSMS.CustomerInformationRequest(
                                                           Destination:               SourceRouting.To(chargingStationId),
                                                           CustomerInformationRequestId:   RandomExtensions.RandomInt32(),
                                                           Report:                         true,
                                                           Clear:                          false,
                                                           CustomerIdentifier:             null,
                                                           IdToken:                        new OCPPv2_1.IdToken(
                                                                                               Value:             commandArray[1],
                                                                                               Type:              OCPPv2_1.IdTokenType.ISO14443,
                                                                                               AdditionalInfos:   null
                                                                                           ),
                                                           CustomerCertificate:            null
                                                       )
                                                   );

                                    DebugX.Log(commandArray.AggregateWith(" ") + " => " + response.Runtime.TotalMilliseconds + " ms");
                                    DebugX.Log(response.ToJSON().ToString());

                                }

                                #endregion

                            }

                        }

                    }

                }

                #region Handle exceptions

                catch (CommandException e)
                {
                    DebugX.Log($"Invalid command: {e.Message}");
                }
                catch (Exception e)
                {
                    DebugX.LogException(e);
                }

                #endregion

            } while (!quit);

            await testLCv2_1.Shutdown();

            foreach (var DebugListener in Trace.Listeners)
                (DebugListener as TextWriterTraceListener)?.Flush();

            #endregion


        }

    }

}
