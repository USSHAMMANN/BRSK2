using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using mvc_app.Api;
using mvc_app.Models;
using Newtonsoft.Json;
using System.Diagnostics;

namespace mvc_app.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        Api.Api api;
        CookieManager cookieManager;
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger, IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
            cookieManager = new CookieManager(httpContextAccessor);
            _logger = logger;
        }

        public IActionResult Index()
        {
/*            ViewBag.UserInfo = JsonConvert.DeserializeObject<User>(cookieManager.GetCookie("user").Value);
*/            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}