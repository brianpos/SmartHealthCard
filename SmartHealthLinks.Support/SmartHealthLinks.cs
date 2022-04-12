using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SmartHealthLinks.Support
{
    public class SmartLinks
    {
        public string access_token { get; set; }
        public int? expires_in { get; set; }
        public IEnumerable<SmartResourceAccessRights> authorization_details { get; set; }
    }

    public class SmartResourceAccessRights
    {
        /// <summary>
        ///  "shlink-view" | "smart-on-fhir-api"
        /// </summary>
        public string type { get; set; }
        public IEnumerable<string> locations { get; set; }
        public IEnumerable<string> actions { get; set; }
        public IEnumerable<string> datatypes { get; set; }
    }

    public class SmartRegistrationRequest
    {
        public string token_endpoint_auth_method { get; set; }
        public IEnumerable<string> grant_types { get; set; }
        public SmartRegistrationKeys jwks { get; set; }
        public string client_name { get; set; }
        public IEnumerable<string> contacts { get; set; }
    }

    public class SmartRegistrationResponse
    {
        public string client_id { get; set; }
        public string scope { get; set; }
        public IEnumerable<string> grant_types { get; set; }
        public SmartRegistrationKeys jwks { get; set; }
        public string client_name { get; set; }
        public IEnumerable<string> contacts { get; set; }
        public string token_endpoint_auth_method { get; set; }
    }

    public class SmartRegistrationKeys
    {
        public IEnumerable<JsonWebKey> keys { get; set; }
    }

    public class SmartLinksToken
    {
        public SmartLinksOAuth oauth { get; set; }
        public string flags { get; set; }
        public string decrypt { get; set; }
        public string prefix { get; set; }

        /// <summary>
        /// Expiry Epoch seconds
        /// (to check if the QR is stale)
        /// </summary>
        public int? exp { get; set; }
    }

    public class SmartLinksOAuth
    {
        public string url { get; set; }
        public string token { get; set; }
    }

    public class VerifiableCredentials
    {
        public IEnumerable<string> verifiableCredential { get; set; }
    }
}
