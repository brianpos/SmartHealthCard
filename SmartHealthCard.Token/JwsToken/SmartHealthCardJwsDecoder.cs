using SmartHealthCard.Token.Encoders;
using SmartHealthCard.Token.Exceptions;
using SmartHealthCard.Token.Model.Jwks;
using SmartHealthCard.Token.Model.Jws;
using SmartHealthCard.Token.Providers;
using SmartHealthCard.Token.Serializers.Json;
using SmartHealthCard.Token.Serializers.Jws;
using SmartHealthCard.Token.Support;
using SmartHealthCard.Token.Validators;
using System;
using System.Threading.Tasks;

namespace SmartHealthCard.Token.JwsToken
{
  public sealed class SmartHealthCardJwsDecoder : IJwsDecoder
  {
    private readonly IJsonSerializer? JsonSerializer;
    private readonly IJwsHeaderSerializer HeaderSerializer;
    private readonly IJwsPayloadSerializer PayloadSerializer;
    private readonly IJwsSignatureValidator? JwsSignatureValidator;
    private readonly IJwsPayloadValidator? JwsPayloadValidator;
    private readonly IJwsHeaderValidator? JwsHeaderValidator;
    private readonly IJwksProvider? JwksProvider;
    public SmartHealthCardJwsDecoder(
      IJwsHeaderSerializer HeaderSerializer,
      IJwsPayloadSerializer PayloadSerializer)
    {
      this.HeaderSerializer = HeaderSerializer;
      this.PayloadSerializer = PayloadSerializer;
    }

    public SmartHealthCardJwsDecoder(
      IJsonSerializer JsonSerializer,
      IJwsHeaderSerializer HeaderSerializer,
      IJwsPayloadSerializer PayloadSerializer,
      IJwksProvider? JwksProvider,
      IJwsSignatureValidator? IJwsSignatureValidator,
      IJwsHeaderValidator? JwsHeaderValidator,
      IJwsPayloadValidator? IJwsPayloadValidator)
      : this(HeaderSerializer, PayloadSerializer)
    {      
      this.JsonSerializer = JsonSerializer ?? new JsonSerializer();

      this.JwksProvider = JwksProvider ?? new JwksProvider(this.JsonSerializer);
      this.JwsSignatureValidator = IJwsSignatureValidator ?? new JwsSignatureValidator();
      this.JwsHeaderValidator = JwsHeaderValidator ?? new SmartHealthCardHeaderValidator();
      this.JwsPayloadValidator = IJwsPayloadValidator ?? new SmartHealthCardPayloadValidator();
    }

    public async Task<PayloadType> DecodePayloadAsync<HeaderType, PayloadType>(string Token, bool Verity = false)
    {
      if (string.IsNullOrEmpty(Token))
        throw new InvalidTokenException("The Token provided was found to be null or empty.");

      string Payload = new JwsParts(Token).Payload;
      byte[] DecodedPayload = Base64UrlEncoder.Decode(Payload);
      PayloadType PayloadDeserialized = await PayloadSerializer.DeserializeAsync<PayloadType>(DecodedPayload);

      if (!Verity)
      {
        return await Task.FromResult(PayloadDeserialized);
      }
      else
      {
        //We must use the PayloadSerializer.Deserialize and not the JsonSerializer.FromJson() because for 
        //SMART Health Cards the payload is DEFLATE compressed bytes and not a JSON string
        JwsBody JwsBody = await PayloadSerializer.DeserializeAsync<JwsBody>(DecodedPayload);

        if (JwsBody.Iss is null)
          throw new SignatureVerificationException("No Issuer (iss) claim found in JWS Token body.");

        if (!Uri.TryCreate($"{JwsBody.Iss}/.well-known/jwks.json", UriKind.Absolute, out Uri? WellKnownJwksUri))
          throw new SignatureVerificationException($"Unable to parse the Issuer (iss) claim to a absolute Uri, value was {$"{JwsBody.Iss}/.well-known/jwks.json"}");

        if (JwksProvider is null)
          throw new SignatureVerificationException($"When Verify is true {nameof(this.JwksProvider)} must be not null.");
        
        Result<JsonWebKeySet> JsonWebKeySetResult = await JwksProvider.GetJwksAsync(WellKnownJwksUri);
        JsonWebKeySet JsonWebKeySet;
        if (JsonWebKeySetResult.Success)
        {
          JsonWebKeySet = JsonWebKeySetResult.Value;          
        }
        else
        {
          throw new SignatureVerificationException($"Unable to obtain the JsonWebKeySet (JWKS) from : {WellKnownJwksUri.OriginalString}. ErrorMessage: {JsonWebKeySetResult.ErrorMessage}");
        }

        string Header = new JwsParts(Token).Header;
        byte[] DecodedHeader = Base64UrlEncoder.Decode(Header);
        string HeaderJson = Utf8EncodingSupport.GetString(DecodedHeader);

        if (JsonSerializer is null)
          throw new SignatureVerificationException($"When Verify is true {nameof(this.JsonSerializer)} must be not null.");

        JwsHeader JwsHeader = JsonSerializer.FromJson<JwsHeader>(HeaderJson);

        if (JwsHeader.Kid is null)
          throw new SignatureVerificationException("No key JWK Thumb-print (kid) claim found in JWS Token header.");

        Algorithms.IAlgorithm Algorithm = Algorithms.ES256Algorithm.FromJWKS(JwsHeader.Kid, JsonWebKeySet, JsonSerializer);

        if (this.JwsSignatureValidator is null)
          throw new NullReferenceException($"When Verify is true {nameof(this.JwsSignatureValidator)} must be not null.");

        JwsSignatureValidator.Validate(Algorithm, Token);

        if (this.JwsHeaderValidator is null)
          throw new NullReferenceException($"When Verify is true {nameof(this.JwsHeaderValidator)} must be not null.");

        this.JwsHeaderValidator.Validate(this.DecodeHeaderAsync<HeaderType>(Token));

        if (this.JwsPayloadValidator is null)
          throw new NullReferenceException($"When Verify is true {nameof(this.JwsPayloadValidator)} must be not null.");

        this.JwsPayloadValidator.Validate(PayloadDeserialized);

        return PayloadDeserialized;
      }
    }

    public async Task<HeaderType> DecodeHeaderAsync<HeaderType>(string Token)
    {
      if (string.IsNullOrEmpty(Token))
      {
        throw new ArgumentException(nameof(Token));
      }
      string Header = new JwsParts(Token).Header;
      byte[] DecodedHeader = Base64UrlEncoder.Decode(Header);
      return await HeaderSerializer.DeserializeAsync<HeaderType>(DecodedHeader);
    }

  }
}