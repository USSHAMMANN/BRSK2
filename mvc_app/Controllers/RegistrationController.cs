using Microsoft.AspNetCore.Mvc;
using mvc_app.Models;
using System.Net;

namespace mvc_app.Controllers
{
    public class RegistrationController : Controller
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        Api.Api api;
        public RegistrationController(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
            string token = _httpContextAccessor.HttpContext.Request.Cookies["token"];
            api = new Api.Api(httpContextAccessor);
        }
        public IActionResult Index()
        {
            return View();
        }

        public async Task<ActionResult> Registration(UserRegistration loginModel)
        {
            bool registration = await api.UserRegistrationAsync(loginModel.UserLogin, loginModel.UserPassword, loginModel.UserEmail, loginModel.UserName);
            if (registration)
            {
                return RedirectToAction("Index", "Home");
            }
            else if (!registration)
            {
                TempData["IncorrectRegistration"] = "Логин уже существует";
                return RedirectToAction("Index", "Registration");
            }
            else
            {
                return BadRequest();
            }

        }
    }
}
