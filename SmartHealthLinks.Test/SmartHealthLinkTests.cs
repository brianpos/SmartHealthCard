using Hl7.Fhir.Model;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Formatting;
using Task = System.Threading.Tasks.Task;
using SmartHealthLinks.Support;
using Hl7.Fhir.Support;

namespace SmartHealthLinks.Test
{
    [TestClass]
    public class SmartHealthLinksTests
    {
        [TestMethod]
        public async Task SmartLinksTester()
        {
            // decode Link (reading it from the URL)
            string smartLinkUrl = "https://demo.vaxx.link/viewer#shlink:/eyJvYXV0aCI6eyJ1cmwiOiJodHRwczovL2FwaS52YXh4LmxpbmsiLCJ0b2tlbiI6ImFtNUFteEpRS1NmZkIyeS1QQUlwQTJHSlRqYW5HNExjUC1YdXB2YXRRbkEifSwiZmxhZ3MiOiJQIiwiZGVjcnlwdCI6ImNlU1dMZXFXbWdPT1RoejBYUFo4UXRTY3dQLTdKYUpva0gta253UW11djAifQ";
            const string smartLinkName = "#shlink:/";
            var indexLink = smartLinkUrl.IndexOf(smartLinkName);
            if (indexLink < 0)
            {
                throw new Exception("No Smart Link encoded in the link");
            }
            string link = smartLinkUrl.Substring(indexLink + smartLinkName.Length);
            var smartLinkToken = Base64UrlEncoder.Decode(link);
            System.Diagnostics.Trace.WriteLine(smartLinkToken);

            // retrieve the content from the provided URL
            var linkDetails = Newtonsoft.Json.JsonConvert.DeserializeObject<SmartLinksToken>(smartLinkToken);

            HttpClient client = new HttpClient();

            // retrieve the OAuth WellKnown
            // ${url}/.well-known/smart-configuration
            string discoveryUrl = $"{linkDetails.oauth.url}/.well-known/smart-configuration";
            var content = await client.GetAsync(discoveryUrl);
            string contentJson = await content.Content.ReadAsStringAsync();
            System.Diagnostics.Trace.WriteLine(contentJson);

            var appLaunchConfiguration = JsonConvert.DeserializeObject<FhirSmartAppLaunchConfiguration>(contentJson);
            // Check that the app configuration has the required stuff in it
            Assert.IsTrue(appLaunchConfiguration.capabilities.Contains("shlinks"), "`shlinks` verify this capability is listed");
            Assert.IsTrue(!string.IsNullOrEmpty(appLaunchConfiguration.registration_endpoint));
            Assert.IsTrue(!string.IsNullOrEmpty(appLaunchConfiguration.token_endpoint));
            Assert.IsTrue(appLaunchConfiguration.token_endpoint_auth_methods_supported.Contains("private_key_jwt"), "`private_key_jwt` verify this token_endpoint_auth_methods_supported is listed");

            // Dynamic Client Registration
            string pin = "1234"; // this is the PIN that was encoded into the QR (provided out of band - likely by the user)

            // Create a new private/public key pair and register them
            var rsaCrypto = new System.Security.Cryptography.RSACryptoServiceProvider(2048);
            var rkey = new RsaSecurityKey(rsaCrypto.ExportParameters(false));
            var k = JsonWebKeyConverter.ConvertFromRSASecurityKey(rkey);

            var regDetails = new SmartRegistrationRequest()
            {
                token_endpoint_auth_method = "private_key_jwt",
                grant_types = new[] { "client_credentials" },
                jwks = new SmartRegistrationKeys()
                {
                    keys = new[] { k } // need to put in our public key here
                },
                client_name = "Dr Brian",
                contacts = new[] { "dr.brian@example.org" }
            };

            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", linkDetails.oauth.token);
            client.DefaultRequestHeaders.Add("shlink-pin", pin);
            var jsonFormatter = new JsonMediaTypeFormatter();
            jsonFormatter.SerializerSettings.DefaultValueHandling = DefaultValueHandling.Include;
            jsonFormatter.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
            jsonFormatter.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver(); // for the JSonWebKey serialization (as default has bad casing)
            content = await client.PostAsync<SmartRegistrationRequest>(appLaunchConfiguration.registration_endpoint, regDetails, jsonFormatter);
            contentJson = await content.Content.ReadAsStringAsync();
            System.Diagnostics.Trace.WriteLine(contentJson);

            var regResponse = JsonConvert.DeserializeObject<SmartRegistrationResponse>(contentJson);

            // Gererate an Authentication JWT and request an access token
            var payload = new
            {
                iss = regResponse.client_id,
                sub = regResponse.client_id,
                aud = appLaunchConfiguration.token_endpoint,
                exp = EpochTime.GetIntDate(DateTime.Now.AddMinutes(5)),
                nbf = EpochTime.GetIntDate(DateTime.Now),
                jti = Guid.NewGuid().ToFhirId(),
            };

            // (Including the extraHeaders here includes the public key in the JWT, and thus can have its signature validated more easily be things like jwt.io
            //  they are not strictly required, and the OAuth server will be checking the public key that was registered for this client anyway)
            var extraHeaders = new System.Collections.Generic.Dictionary<string, object>();
            extraHeaders.Add("typ", "JWT");
            extraHeaders.Add(JwtHeaderParameterNames.Jwk, k);
            string assertion = Jose.JWT.Encode(payload, rsaCrypto, Jose.JwsAlgorithm.RS256, extraHeaders);
            System.Diagnostics.Trace.WriteLine(assertion);

            // Fetch an access token to talk to the server
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
            List<KeyValuePair<string, string>> values = new List<KeyValuePair<string, string>>();
            values.Add(new KeyValuePair<string, string>("scope", regResponse.scope));
            values.Add(new KeyValuePair<string, string>("grant_type", "client_credentials"));
            values.Add(new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
            values.Add(new KeyValuePair<string, string>("client_assertion", assertion));
            FormUrlEncodedContent contentUrl = new FormUrlEncodedContent(values);
            try
            {
                content = await client.PostAsync(appLaunchConfiguration.token_endpoint, contentUrl);
                contentJson = await content.Content.ReadAsStringAsync();
                System.Diagnostics.Trace.WriteLine(contentJson);

                // Now read the actual links
                SmartLinks actualLinks = JsonConvert.DeserializeObject<SmartLinks>(contentJson);
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", actualLinks.access_token);
                foreach (var linkedFile in actualLinks.authorization_details)
                {
                    foreach (var locationUrl in linkedFile.locations)
                    {
                        System.Diagnostics.Trace.WriteLine("---------------------------------------");
                        System.Diagnostics.Trace.WriteLine($"{locationUrl}");

                        content = await client.GetAsync(locationUrl);
                        contentJson = await content.Content.ReadAsStringAsync();
                        System.Diagnostics.Trace.WriteLine(contentJson);

                        if (!string.IsNullOrEmpty(linkDetails.decrypt))
                        {
                            // Need to decruypt the content first.
                            var decryptKey = Base64UrlEncoder.DecodeBytes(linkDetails.decrypt);
                            contentJson = Jose.JWT.Decode(contentJson, decryptKey, Jose.JweAlgorithm.DIR, Jose.JweEncryption.A256GCM);
                        }

                        var vc = JsonConvert.DeserializeObject<VerifiableCredentials>(contentJson);
                        foreach (var credential in vc?.verifiableCredential)
                        {
                            // decode this credential
                            var parts = credential.Split('.');
                            JwtHeader header = JwtHeader.Base64UrlDeserialize(parts[0]);
                            var kid = Base64UrlEncoder.DecodeBytes(header["kid"] as string);
                            var body = System.Text.UTF8Encoding.UTF8.GetString(new DeflateCompressionProvider().Decompress(Base64UrlEncoder.DecodeBytes(parts[1])));
                            var jwt = new JwtSecurityToken(header, JwtPayload.Deserialize(body), parts[0], body, parts[1]);

                            // Need to check the validity of the token here
                            System.Diagnostics.Trace.WriteLine(body);
                            Newtonsoft.Json.Linq.JObject jwtBody = Newtonsoft.Json.Linq.JObject.Parse(body);
                            var fhirVersion = jwtBody.SelectToken("vc.credentialSubject.fhirVersion");
                            var bundleJson = jwtBody.SelectToken("vc.credentialSubject.fhirBundle");
                            var bundle = new Hl7.Fhir.Serialization.FhirJsonParser().Parse<Bundle>(bundleJson.ToString());
                            // BasicFacade.DebugDumpOutputXml(bundle);

                            // And resolve the coding display from the content
                        }
                    }
                }
            }
            catch (InvalidOperationException ex)
            {
                System.Diagnostics.Trace.WriteLine(ex.Message);
            }
        }
    }
}
