using ApiGrup.Application.Common.Exceptions;
using ApiGrup.Application.Common.Interfaces;
using ApiGrup.Domain.Entities;
using MediatR;
using System.Threading;
using System.Threading.Tasks;

namespace ApiGrup.Application.TodoItems.Commands.UpdateTodoItem
{
    public class UpdateApiUserCommand : IRequest
    {
        public int Id { get; set; }
        public string Password { get; set; }

        public bool Enabled { get; set; }
    }

    public class UpdateTodoItemCommandHandler : IRequestHandler<UpdateApiUserCommand>
    {
        private readonly IApiDbContext _context;

        public UpdateTodoItemCommandHandler(IApiDbContext context)
        {
            _context = context;
        }

        public async Task<Unit> Handle(UpdateApiUserCommand request, CancellationToken cancellationToken)
        {
            var entity = await _context.ApiUsers.FindAsync(request.Id);

            if (entity == null)
            {
                throw new NotFoundException(nameof(ApiUser), request.Id);
            }

            entity.Password = request.Password;
            entity.Enabled = request.Enabled;

            await _context.SaveChangesAsync(cancellationToken);

            return Unit.Value;
        }
    }
}
