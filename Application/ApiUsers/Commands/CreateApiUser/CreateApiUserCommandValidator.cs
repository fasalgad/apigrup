using FluentValidation;

namespace ApiGrup.Application.Login.Commands.CreateTodoItem
{
    public class CreateApiUserCommandValidator : AbstractValidator<LoginCommand>
    {
        public CreateApiUserCommandValidator()
        {
            RuleFor(v => v.Username)
                .MaximumLength(50)
                .NotEmpty();

            RuleFor(v => v.Password)
                .MaximumLength(50)
                .NotEmpty();
        }
    }
}
