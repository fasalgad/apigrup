using AutoMapper;
using ApiGrup.Application.Common.Mappings;
using ApiGrup.Domain.Entities;
using System;

namespace ApiGrup.Application.TodoLists.Queries.GetApiUsers
{
    public class ApiUserDto : IMapFrom<ApiUser>
    {
        public int Id { get; set; }

        public int Username { get; set; }

        public bool Enabled { get; set; }

        public DateTime CreatedOn { get; set; }

        //EJEMPLO DE MAPPING DE PROPIEDADES QUE NO SON IDENTICOS
        //public void Mapping(Profile profile)
        //{
        //    profile.CreateMap<TodoItem, TodoItemDto>()
        //        .ForMember(d => d.Priority, opt => opt.MapFrom(s => (int)s.Priority));
        //}
    }
}
