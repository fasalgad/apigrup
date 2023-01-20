using ApiGrup.Application.Common.Interfaces;
using ApiGrup.Infrastructure.Options;
using ApiGrup.Infrastructure.Persistence;
using ApiGrup.Infrastructure.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ApiGrup.Infrastructure
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<ApiDbContext>(options =>
                options.UseSqlServer(
                    configuration.GetConnectionString("DefaultConnection"),
                    b => b.MigrationsAssembly(typeof(ApiDbContext).Assembly.FullName)));
            

            services.AddScoped<IApiDbContext>(provider => provider.GetService<ApiDbContext>());

            services.AddScoped<IDomainEventService, DomainEventService>();

            //services.AddDefaultIdentity<ApplicationUser>()
            //    .AddRoles<IdentityRole>()
            //    .AddEntityFrameworkStores<ApiDbContext>();

            //services.AddIdentityServer()
            //    .AddApiAuthorization<ApplicationUser, ApiDbContext>();

            //services.AddTransient<IIdentityService, IdentityService>();

            services.AddTransient<IDateTime, DateTimeService>();

            services.AddSingleton<HttpContextAccessor>();
            services.AddSingleton<IPasswordService, PasswordService>();
            

            services.AddAuthentication()
                .AddIdentityServerJwt();

            services.AddAuthorization(options =>
            {
                options.AddPolicy("CanPurge", policy => policy.RequireRole("Administrator"));
            });

            services.Configure<PasswordOptions>(configuration.GetSection("PasswordOptions"));


            return services;
        }
    }
}
