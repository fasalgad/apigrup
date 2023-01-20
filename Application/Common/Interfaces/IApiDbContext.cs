using ApiGrup.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using System.Threading;
using System.Threading.Tasks;

namespace ApiGrup.Application.Common.Interfaces
{
    public interface IApiDbContext
    {
        DbSet<ApiUser> ApiUsers { get; set; }


        Task<int> SaveChangesAsync(CancellationToken cancellationToken);
    }
}
