﻿using Newtonsoft.Json;
using SmartHealthCard.Token.Encoders;
using SmartHealthCard.Token.Exceptions;
using SmartHealthCard.Token.Providers;
using SmartHealthCard.Token.Serializers.Jws;
using SmartHealthCard.Token.Support;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using static SmartHealthCard.Token.Encoders.Utf8EncodingSupport;

namespace SmartHealthCard.Token.Serializers.Json
{
  public class JsonSerializer : IJwsHeaderSerializer, IJwsPayloadSerializer, IJsonSerializer
  {
    private readonly Newtonsoft.Json.JsonSerializer Serializer;

    public JsonSerializer()
    {
      this.Serializer = Newtonsoft.Json.JsonSerializer.CreateDefault();      
    }

    public virtual async Task<byte[]> SerializeAsync<T>(T Obj, bool Minified = true)
    {      
      return await Task.Run(() => GetBytes(this.ToJson(Obj, Minified)));     
    }
    
    public virtual async Task<T> DeserializeAsync<T>(byte[] bytes)
    {
      T? Item = await Task.Run(() => this.FromJson<T>(GetString(bytes)));
      if (Item is null)
        throw new DeserializationException($"Unable to deserialize the JWS Header to type {typeof(T).Name}");
      return Item;      
    }

    public string ToJson<T>(T Obj, bool Minified = true)
    {
      if (!Minified)
        Serializer.Formatting = Formatting.Indented;

      var Builder = new StringBuilder();
      using var StringWriter = new StringWriter(Builder);
      using var JsonWriter = new  JsonTextWriter(StringWriter);
      Serializer.Serialize(JsonWriter, Obj);      
      return Builder.ToString();
    }

    public T FromJson<T>(string Json)
    {      
      using var StringReader = new StringReader(Json);
      using var JsonReader = new JsonTextReader(StringReader);
      T? Item = Serializer.Deserialize<T>(JsonReader);
      if (Item is null)
        throw new DeserializationException($"Unable to deserialize the JWS Header to type {typeof(T).Name}");
      return Item;
    }

    public Result<T> FromJsonStream<T>(Stream JsonStream)
    {      
      try 
      {
        using (var streamReader = new StreamReader(JsonStream))
        {
          using (var jsonReader = new JsonTextReader(streamReader))
          {
            T? Item = Serializer.Deserialize<T>(jsonReader);
            if (Item is null)
              throw new DeserializationException($"Unable to deserialize the JWS Header to type {typeof(T).Name}");

            return Result<T>.Ok(Item);
          }
        }
      }
      catch(Exception Exec)
      {
        return Result<T>.Fail($"Unable to parser the returned content to JWKS. Message: {Exec.Message }");
      }            
    }


  } 
}
