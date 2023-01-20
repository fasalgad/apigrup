using ApiGrup.Application.Login.Commands;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace ApiGrup.Controllers
{
    public class TokenController : ApiControllerBase
    {
        [HttpPost]
        public async Task<ActionResult<TokenDto>> Authentication(LoginCommand command)
        {
            return await Mediator.Send(command);
        }
    }
}
