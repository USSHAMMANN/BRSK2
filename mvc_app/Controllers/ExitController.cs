using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using mvc_app.Api;

namespace mvc_app.Controllers
{
    public class ExitController : Controller
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        CookieManager cookieManager;
        public ExitController(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
            cookieManager = new CookieManager(httpContextAccessor);
        }
        public IActionResult Index()
        {
            cookieManager.RemoveCookie("token");
            cookieManager.RemoveCookie("login");
            cookieManager.RemoveCookie("password");
            _httpContextAccessor.HttpContext.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}
