using AutoMapper;
using AutoMapper.QueryableExtensions;
using ApiGrup.Application.Common.Interfaces;
using ApiGrup.Application.Common.Mappings;
using ApiGrup.Application.Common.Models;
using MediatR;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ApiGrup.Application.TodoLists.Queries.GetApiUsers;

namespace ApiGrup.Application.TodoItems.Queries.GetApiUsersWithPagination
{
    public class GetApiUsersWithPaginationQuery : IRequest<PaginatedList<ApiUserDto>>
    {
        public int PageNumber { get; set; } = 1;
        public int PageSize { get; set; } = 10;
    }

    public class GetTodoItemsWithPaginationQueryHandler : IRequestHandler<GetApiUsersWithPaginationQuery, PaginatedList<ApiUserDto>>
    {
        private readonly IApiDbContext _context;
        private readonly IMapper _mapper;

        public GetTodoItemsWithPaginationQueryHandler(IApiDbContext context, IMapper mapper)
        {
            _context = context;
            _mapper = mapper;
        }

        public async Task<PaginatedList<ApiUserDto>> Handle(GetApiUsersWithPaginationQuery request, CancellationToken cancellationToken)
        {
            return await _context.ApiUsers
                .ProjectTo<ApiUserDto>(_mapper.ConfigurationProvider)
                .PaginatedListAsync(request.PageNumber, request.PageSize); ;
        }
    }
}
