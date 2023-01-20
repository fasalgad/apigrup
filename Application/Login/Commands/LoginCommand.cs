using ApiGrup.Application.Common.Interfaces;
using MediatR;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System;
using Microsoft.EntityFrameworkCore;
using ApiGrup.Domain.Entities;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace ApiGrup.Application.Login.Commands
{
    public class LoginCommand : IRequest<TokenDto>
    {
        public string Username { get; set; }
        public string Password { get; set; }

    }

    public class LoginCommandHandler : IRequestHandler<LoginCommand, TokenDto>
    {
        private readonly IApiDbContext _context;
        private readonly IPasswordService _passwordService;
        private readonly IConfiguration _configuration;

        public LoginCommandHandler(IApiDbContext context, IPasswordService passwordService, IConfiguration configuration)
        {
            _context = context;
            _passwordService = passwordService;
            _configuration = configuration;
        }

        public async Task<TokenDto> Handle(LoginCommand request, CancellationToken cancellationToken)
        {
            //var pass = _passwordService.Hash(request.Password);

            var user = await _context.ApiUsers.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user == null)
                throw new UnauthorizedAccessException();

            if (!_passwordService.Check(user.Password, request.Password))
            {
                user.CountErrors++;
                await this._context.SaveChangesAsync(cancellationToken);
                await Notificacion(user);
                throw new UnauthorizedAccessException();
            }


            var token = GenerateToken(user);

            var res = new TokenDto
            {
                Token = token,
                ExpireIn = int.Parse(_configuration["Authentication:ExpireIn"])
            };

            return res;
        }

        private string GenerateToken(ApiUser user)
        {
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Authentication:SecretKey"]));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var header = new JwtHeader(signingCredentials);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Username),
            };

            var payload = new JwtPayload(
                _configuration["Authentication:Issuer"],
                _configuration["Authentication:Audience"],
                claims,
                DateTime.Now,
                DateTime.UtcNow.AddMinutes(int.Parse(_configuration["Authentication:ExpireIn"]))
            );

            var token = new JwtSecurityToken(header, payload);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task Notificacion(ApiUser user)
        {

            // var client = new SendGridClient(_appSettings.SENDGRID_API_KEY);
            var client = new SendGridClient("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");
            var from = new EmailAddress("salgado.fabian@gmail.com", "Soporte");
            var subject = "Error";
            var to = new EmailAddress(user.Email, user.Username);
            var plainTextContent = @"¡Hola " + user.Username + @"!
                                Hola, detectamos que se intentó ingresar a tu cuenta, si no fuiste tú, te encargamos ingresar nuevamente al sitio y cambiar la contraseña "
                                + "\n Número de intentos:" + user.CountErrors + @"
                                ";
            var htmlContent = @" 
                        <h1>¡Hola " + user.Username + @"!</h1>
                        <p>Hola, detectamos que se intentó ingresar a tu cuenta, si no fuiste tú, te encargamos ingresar nuevamente al sitio y cambiar la contraseña </ p>
                        <p>Número de intentos:" + user.CountErrors + @"</p>
                       ";
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);
            Response response = await client.SendEmailAsync(msg);
        }

    }
}
