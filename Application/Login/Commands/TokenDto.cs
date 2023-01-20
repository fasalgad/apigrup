using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ApiGrup.Application.Login.Commands
{
    public class TokenDto
    {
        public string Token { get; set; }
        public int ExpireIn { get; set; }
    }
}
