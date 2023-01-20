using ApiGrup.Application.Common.Interfaces;
using ApiGrup.Domain.Entities;
using ApiGrup.Domain.Events;
using MediatR;
using System.Threading;
using System.Threading.Tasks;

namespace ApiGrup.Application.Login.Commands.CreateTodoItem
{
    public class LoginCommand : IRequest<int>
    {
        public string Username { get; set; }
        public string Password { get; set; }

    }

    public class LoginCommandHandler : IRequestHandler<LoginCommand, int>
    {
        private readonly IApiDbContext _context;

        public LoginCommandHandler(IApiDbContext context)
        {
            _context = context;
        }

        public async Task<int> Handle(LoginCommand request, CancellationToken cancellationToken)
        {
            var entity = new ApiUser
            {
                Username = request.Username,
                Password = request.Password,
                Enabled = true,
            };

            entity.DomainEvents.Add(new ApiUserCreatedEvent(entity));

            _context.ApiUsers.Add(entity);

            await _context.SaveChangesAsync(cancellationToken);

            return entity.Id;
        }
    }
}
