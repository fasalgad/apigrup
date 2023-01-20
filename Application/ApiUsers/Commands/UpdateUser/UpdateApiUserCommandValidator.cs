using FluentValidation;

namespace ApiGrup.Application.TodoItems.Commands.UpdateTodoItem
{
    public class UpdateApiUserCommandValidator : AbstractValidator<UpdateApiUserCommand>
    {
        public UpdateApiUserCommandValidator()
        {
            RuleFor(v => v.Id)
                .NotEmpty();

            RuleFor(v => v.Password)
                .MaximumLength(200)
                .NotEmpty();
        }
    }
}
