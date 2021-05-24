﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SmartHealthCard.Token.Exceptions
{
  class DeserializationException : SmartHealthCardException
  {
    public DeserializationException(string Message)
        : base(Message)
    {
    }
  }
}
