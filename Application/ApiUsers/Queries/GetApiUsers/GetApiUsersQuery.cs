using ApiGrup.Application.Common.Interfaces;
using AutoMapper;
using AutoMapper.QueryableExtensions;
using MediatR;
using Microsoft.EntityFrameworkCore;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace ApiGrup.Application.TodoLists.Queries.GetApiUsers
{
    public class GetApiUsersQuery : IRequest<List<ApiUserDto>>
    {
    }

    public class GetApiUsersQueryHandler : IRequestHandler<GetApiUsersQuery, List<ApiUserDto>>
    {
        private readonly IApiDbContext _context;
        private readonly IMapper _mapper;

        public GetApiUsersQueryHandler(IApiDbContext context, IMapper mapper)
        {
            _context = context;
            _mapper = mapper;
        }

        public async Task<List<ApiUserDto>> Handle(GetApiUsersQuery request, CancellationToken cancellationToken)
        {
            var vm = _context.ApiUsers
                    .AsNoTracking()
                    .ProjectTo<ApiUserDto>(_mapper.ConfigurationProvider)
                    .ToListAsync(cancellationToken);

            return await vm;
        }
    }
}
