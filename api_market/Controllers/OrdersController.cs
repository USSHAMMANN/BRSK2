using api_market.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Security.Claims;

namespace api_market.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OrdersController : ControllerBase
    {
        db_marketContext dbContext = new db_marketContext();
        [HttpGet]
        [Authorize]
        public async Task<ActionResult<List<Order>>> GetCurrentUserOrders()
        {
            var user = GetCurrectUser();

            List<Order> orders = dbContext.Orders
                .Include(x => x.User)
                .Include(p => p.OrderLists)
                .ThenInclude(p => p.Product)
                .Where(x => x.UserId == user.UserId)
                .ToList();
            if (orders.Count == 0)
            {
                return NoContent();
            }
            return Ok(orders);
        }
        [HttpGet]
        [Route("UsersOrders")]
        [Authorize(Roles = "Администратор магазина")]
        public async Task<ActionResult<List<Order>>> GetUsersOrders()
        {
            List<Order> orders = dbContext.Orders
                .Include(x => x.User)
                .Include(p => p.OrderLists)
                .ThenInclude(p => p.Product)
                .ToList();

            if (orders.Count == 0)
            {
                return NoContent();
            }
            return Ok(orders);
        }
        [HttpGet]
        [Authorize(Roles = "Администратор магазина")]
        [Route("UserOrdersByName/{userName}")]
        public async Task<ActionResult<List<Order>>> GetUsersOrders(string userName)
        {
            List<Order> orders = dbContext.Orders
                .Where(x => x.User.UserName.Contains(userName))
                .Include(x => x.User)
                .Include(p => p.OrderLists)
                .ThenInclude(p => p.Product)
                .ToList();

            if (orders.Count == 0)
            {
                return NoContent();
            }
            return Ok(orders);
        }

        [HttpGet]
        [Authorize(Roles = "Администратор магазина")]
        [Route("{user_id}")]
        public async Task<ActionResult<List<Order>>> GetUserOrders(int user_id)
        {
            List<Order> orders = dbContext.Orders
                .Include(x => x.User)
                .Include(p => p.OrderLists)
                .ThenInclude(p => p.Product)
                .Where(x => x.UserId == user_id).ToList();

            if (orders.Count == 0)
            {
                return NoContent();
            }
            return Ok(orders);
        }
        [HttpPost]
        [Authorize]

        public async Task<ActionResult> Ordering(List<int> product_id_list)
        {
            product_id_list = product_id_list.Distinct().ToList();

            List<Product> products = dbContext.Products
                .Where(p => product_id_list.Contains(p.ProductId)).ToList();
            User user = GetCurrectUser();
            user = dbContext.Users.Find(user.UserId);
            if (products.Count == 0)
            {
                return NotFound();
            }

            var order = new Order()
            {
                UserId = user.UserId,
                OrderDate = DateTime.Now,
            };
            dbContext.Orders.Add(order);
            dbContext.SaveChanges();
            int id = order.OrderId;
            foreach (var item in products)
            {
                dbContext.OrderLists.Add(new OrderList()
                {
                    OrderId = id,
                    ProductId = item.ProductId,
                });
            }
            dbContext.SaveChanges();


            return Ok();
        }
        [NonAction]
        public User GetCurrectUser()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;
            if (identity != null)
            {
                var userClaims = identity.Claims;

                return new User
                {
                    UserId = Convert.ToInt32(userClaims.FirstOrDefault(o => o.Type == ClaimTypes.NameIdentifier)?.Value),
                    UserName = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Name)?.Value,
                };
            }
            return null;
        }
    }
}
