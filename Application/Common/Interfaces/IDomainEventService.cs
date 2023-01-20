using ApiGrup.Domain.Common;
using System.Threading.Tasks;

namespace ApiGrup.Application.Common.Interfaces
{
    public interface IDomainEventService
    {
        Task Publish(DomainEvent domainEvent);
    }
}
