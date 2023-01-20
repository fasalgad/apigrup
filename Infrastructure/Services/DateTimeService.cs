using ApiGrup.Application.Common.Interfaces;
using System;

namespace ApiGrup.Infrastructure.Services
{
    public class DateTimeService : IDateTime
    {
        public DateTime Now => DateTime.Now;
    }
}
