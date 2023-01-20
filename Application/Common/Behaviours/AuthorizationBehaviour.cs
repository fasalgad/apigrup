using ApiGrup.Application.Common.Exceptions;
using ApiGrup.Application.Common.Interfaces;
using ApiGrup.Application.Common.Security;
using MediatR;
using Microsoft.AspNetCore.Http;
using System;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace ApiGrup.Application.Common.Behaviours
{
    public class AuthorizationBehaviour<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse>
    {
        private readonly ICurrentUserService _currentUserService;
        private readonly HttpContext _httpContent;

        //private readonly IIdentityService _identityService;

        public AuthorizationBehaviour(ICurrentUserService currentUserService, IHttpContextAccessor httpContextAccessor) //, IIdentityService identityService)
        {
            _currentUserService = currentUserService;
            _httpContent = httpContextAccessor.HttpContext;
        }

        public async Task<TResponse> Handle(TRequest request, CancellationToken cancellationToken, RequestHandlerDelegate<TResponse> next)
        {
            var authorizeAttributes = request.GetType().GetCustomAttributes<AuthorizeAttribute>();

            var token = _httpContent.Request.Headers.FirstOrDefault(h => h.Key == "Authorization").Value.FirstOrDefault().Split(" ").Last();

            if (authorizeAttributes.Any())
            {
                // Must be authenticated user
                if (_currentUserService.UserId == null)
                {
                    throw new UnauthorizedAccessException();
                }

                

                //// Must be a member of at least one role in roles
                //if (!authorized)
                //{
                //    throw new ForbiddenAccessException();
                //}
                    
                //}

                // Policy-based authorization
                //var authorizeAttributesWithPolicies = authorizeAttributes.Where(a => !string.IsNullOrWhiteSpace(a.Policy));
                //if (authorizeAttributesWithPolicies.Any())
                //{
                //    foreach (var policy in authorizeAttributesWithPolicies.Select(a => a.Policy))
                //    {
                //        var authorized = await _identityService.AuthorizeAsync(_currentUserService.UserId, policy);

                //        if (!authorized)
                //        {
                //            throw new ForbiddenAccessException();
                //        }
                //    }
                //}
            }

            // User is authorized / authorization not required
            return await next();
        }
    }
}
