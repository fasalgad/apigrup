using ApiGrup.Application.Common.Models;
using System.Threading.Tasks;

namespace ApiGrup.Application.Common.Interfaces
{
    public interface ISecurityService
    {
        Task<string> CripAsync(string text);

        
    }
}
