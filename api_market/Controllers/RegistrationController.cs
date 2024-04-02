using api_market.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using mvc_app.Models;
using System.Net.Mail;

namespace api_market.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RegistrationController : ControllerBase
    {
        db_marketContext dbContext = new db_marketContext();
        [HttpPost]
        public async Task<ActionResult<User>> Post(UserRegistration userRegistration)
        {
            if (dbContext.Users.FirstOrDefault(x => x.UserLogin == userRegistration.UserLogin) != null)
            {
                return Conflict($"Пользователь с логином {userRegistration.UserLogin} уже существует");
            }
            else if (userRegistration.UserLogin.Length < 5 || userRegistration.UserPassword.Length < 8 || userRegistration.UserEmail.Length < 3)
            {
                return BadRequest("Поля недостаточной длины");
            }
            else if (userRegistration.UserLogin.Length > 20 || userRegistration.UserPassword.Length > 20 || userRegistration.UserEmail.Length > 50)
            {
                return BadRequest("Поля превышают требуемую длину");
            }
            try
            {
                MailAddress mailAddress = new MailAddress(userRegistration.UserEmail);
            }
            catch (Exception)
            {

                return BadRequest("Почта не действительна");
            }

            if (dbContext.Users.FirstOrDefault(x => x.UserEmail == userRegistration.UserEmail) != null)
            {
                return Conflict($"Пользователь с почтой {userRegistration.UserEmail} уже существует");
            }

            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(userRegistration.UserPassword); // Хеширование пароля с помощью bcrypt

            User new_user = new User()
            {
                UserPassword = hashedPassword,
                UserLogin = userRegistration.UserLogin,
                UserEmail = userRegistration.UserEmail,
                UserRole = 1,
                UserName = userRegistration.UserName,
            };

            dbContext.Users.Add(new_user);
            dbContext.SaveChanges();

            new_user.UserLogin = "";
            new_user.UserPassword = "";
            return new ObjectResult(new_user) { StatusCode = StatusCodes.Status201Created };
        }
    }
}
