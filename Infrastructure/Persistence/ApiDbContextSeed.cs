using ApiGrup.Domain.Entities;
using System.Linq;
using System.Threading.Tasks;

namespace ApiGrup.Infrastructure.Persistence
{
    public static class ApiDbContextSeed
    {
        public static async Task SeedDefaultUserAsync(ApiDbContext context)
        {
            // Seed, if necessary
            if (!context.ApiUsers.Any())
            {

                context.ApiUsers.Add(new ApiUser { Username="Admin_Grup", Password=""  });

                await context.SaveChangesAsync();
            }
        }
    }
}
