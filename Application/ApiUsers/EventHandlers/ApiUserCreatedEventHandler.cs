using ApiGrup.Application.Common.Models;
using ApiGrup.Domain.Events;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Threading;
using System.Threading.Tasks;

namespace ApiGrup.Application.TodoItems.EventHandlers
{
    public class ApiUserCreatedEventHandler : INotificationHandler<DomainEventNotification<ApiUserCreatedEvent>>
    {
        private readonly ILogger<ApiUserCreatedEventHandler> _logger;

        public ApiUserCreatedEventHandler(ILogger<ApiUserCreatedEventHandler> logger)
        {
            _logger = logger;
        }

        public Task Handle(DomainEventNotification<ApiUserCreatedEvent> notification, CancellationToken cancellationToken)
        {
            var domainEvent = notification.DomainEvent;

            _logger.LogInformation("ApiGrup Domain Event: {DomainEvent}", domainEvent.GetType().Name);

            return Task.CompletedTask;
        }
    }
}
