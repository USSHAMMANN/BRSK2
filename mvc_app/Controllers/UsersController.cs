using Microsoft.AspNetCore.Mvc;
using mvc_app.Api;
using mvc_app.Models;
using Newtonsoft.Json;
using System.Text;

namespace mvc_app.Controllers
{
    public class UsersController : Controller
    {
        ApiUser apiUser;
        public UsersController(IHttpContextAccessor httpContextAccessor) 
        {
            apiUser = new ApiUser(httpContextAccessor);
        }
        public async Task<ActionResult> Index()
        {
            List<User> users = await apiUser.GetUsers();
            return View(users);
        }
        public async Task<ActionResult> Edit(int user_id)
        {
            User user = await apiUser.GetUser(user_id);
            return View(user);
        }

        [HttpPost]
        public async Task<ActionResult> SetRole(int user_id, string role)
        {
            string apiEndpoint = "";

            switch (role)
            {
                case "Admin":
                    apiUser.SetAdminRole(user_id);
                    break;
                case "SysAdmin":
                    apiUser.SetSysAdminRole(user_id);
                    break;
                case "Client":
                    apiUser.SetClientRole(user_id);
                    break;
                default:
                    return BadRequest("Неизвестная роль");
            }

            return RedirectToAction("Index", "Users");
        }

        [HttpGet]
        public async Task<ActionResult> GetUsersByName(string username)
        {
            List<User> users = await apiUser.GetUsersByName(username);
            return PartialView("_Users" ,users);
        }

    }
}
