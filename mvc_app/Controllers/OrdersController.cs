using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using mvc_app.Api;
using mvc_app.Models;

namespace mvc_app.Controllers
{
    [Authorize]
    public class OrdersController : Controller
    {
        readonly IHttpContextAccessor httpContextAccessor;
        ApiOrder apiOrder;
        public OrdersController(IHttpContextAccessor httpContextAccessor) 
        {
            apiOrder = new ApiOrder(httpContextAccessor);
            this.httpContextAccessor = httpContextAccessor;
        }
        public async Task<ActionResult> Index()
        {
            List<Order> orders = new List<Order>(0);
            if (httpContextAccessor.HttpContext.User.IsInRole("Клиент"))
            {
                orders = await apiOrder.GetOrders();
            }
            else
            {
                orders = await apiOrder.GetAllOrders();
            }

            if (orders == null)
            {
                orders = new List<Order>();
            }

            return View(orders);
        }
        [HttpGet]
        public async Task<ActionResult> IndexWithUserId(int user_id)
        {
            List<Order> orders = new List<Order>(0);
            if (httpContextAccessor.HttpContext.User.IsInRole("Клиент"))
            {
                return RedirectToAction("Index");
            }
            else
            {
                orders = await apiOrder.GetUserOrders(user_id);
            }

            if (orders == null)
            {
                orders = new List<Order>();
            }

            return View(orders);
        }

        [HttpGet]
        public async Task<IActionResult> GetOrdersByUserName(string userName = "")
        {
            List<Order> orders = new List<Order>(0);
            if (userName == "" || userName == null)
            {
                orders = await apiOrder.GetAllOrders();
            }
            else
            {
                orders = await apiOrder.GetOrderByUserName(userName);
            }
            return PartialView("_Orders", orders);
        }

    }
}
