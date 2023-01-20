using ApiGrup.Application.Common.Models;
using ApiGrup.Application.Login.Commands.CreateTodoItem;
using ApiGrup.Application.TodoLists.Queries.GetApiUsers;
using ApiGrup.Controllers;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using ApiGrup.Application.TodoItems.Queries.GetApiUsersWithPagination;
using ApiGrup.Application.TodoItems.Commands.UpdateTodoItem;
using ApiGrup.Application.Common.Security;
using NSwag.Annotations;

namespace ApiGrup.WebUI.Controllers
{
    [Authorize]
    public class ApiUsersController : ApiControllerBase
    {
        [HttpGet]
        public async Task<ActionResult<PaginatedList<ApiUserDto>>> GetApiUsersWithPagination([FromQuery] GetApiUsersWithPaginationQuery query)
        {
            return await Mediator.Send(query);
        }

        [HttpPost]
        public async Task<ActionResult<int>> Create(LoginCommand command)
        {
            return await Mediator.Send(command);
        }

        [HttpPut("{id}")]
        public async Task<ActionResult> Update(int id, UpdateApiUserCommand command)
        {
            if (id != command.Id)
            {
                return BadRequest();
            }

            await Mediator.Send(command);

            return NoContent();
        }

    }
}
