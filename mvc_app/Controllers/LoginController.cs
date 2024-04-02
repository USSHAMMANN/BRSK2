using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using mvc_app.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace mvc_app.Controllers
{
    public class LoginController : Controller
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        Api.Api api;
        public LoginController(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
            api = new Api.Api(httpContextAccessor);
        }
        public ActionResult Index()
        {
            return View();
        }
        public async Task<ActionResult> Login(UserLogin loginModel)
        {
            if (await Authorization(loginModel))
            {
                return RedirectToAction("Index", "Home");
            }
            else
            {
                TempData["IncorrectLogin"] = "Неверные данные";
                return RedirectToAction("Index", "Login");
            }
        }

        private async Task<bool> Authorization(UserLogin loginModel)
        {
            Api.TokenResponse tokens = await api.UserLoginAsync(loginModel.Login, loginModel.Password);
            if (tokens.AccessToken.Length != 0)
            {
                await Api.Api.SetTokenForClientAsync(tokens.AccessToken);


                var jwtHandler = new JwtSecurityTokenHandler();
                var readableToken = jwtHandler.ReadJwtToken(tokens.AccessToken);

                var claims = readableToken.Claims;
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                var roleClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.Role);
                if (roleClaim != null)
                {
                    var userRole = roleClaim.Value;
                    identity.AddClaim(new Claim(ClaimTypes.Role, "Администратор магазина"));
                    
                }

                return true;
            }
            return false;
        }
    }
}
