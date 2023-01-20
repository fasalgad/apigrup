using ApiGrup.Application.Common.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ApiGrup.Application.Services
{
    public class SecurityService : ISecurityService
    {
        public Task<string> CripAsync(string text)
        {
            throw new NotImplementedException();
        }
    }
}
