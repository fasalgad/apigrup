using ApiGrup.Domain.Common;
using ApiGrup.Domain.Entities;

namespace ApiGrup.Domain.Events
{
    public class ApiUserCreatedEvent : DomainEvent
    {
        public ApiUserCreatedEvent(ApiUser item)
        {
            Item = item;
        }

        public ApiUser Item { get; }
    }
}
