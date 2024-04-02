using api_market.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace api_market.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductsController : ControllerBase
    {
        db_marketContext dbContext = new db_marketContext();
        [HttpGet]
       
        public async Task<ActionResult<List<Product>>> GetProducts()
        {
            List<Product> products = dbContext.Products.ToList();
            if (products.Count == 0)
            {
                return NoContent();
            }
            return Ok(products);
        }
        [HttpGet]
        [Route("ProductsByName/{product_name}")]
        public async Task<ActionResult<List<Product>>> GetProductsByName(string product_name)
        {
            List<Product> products = dbContext.Products.Where(x => x.ProductName.Contains(product_name)).ToList();
            if (products.Count == 0)
            {
                return NoContent();
            }
            return Ok(products);
        }
        [HttpGet]
        [Route("{product_id}")]
        public async Task<ActionResult<Product>> GetProduct(int product_id)
        {
            Product product = dbContext.Products.Find(product_id);
            if (product == null)
            {
                return NotFound();
            }
            return Ok(product);
        }
        [HttpPut]
        [Authorize(Roles = "Администратор магазина")]
        public async Task<ActionResult<Product>> EditProduct(Product product)
        {
            Product edit_product = dbContext.Products.Find(product.ProductId);
            if (product == null)
            {
                return NotFound();
            }
            dbContext.Products.Update(product);
            dbContext.SaveChanges();
            return Ok(product);
        }
        [HttpPost]
        [Route("ProductRangeList")]
        public async Task<ActionResult> GetProductFromIdList(List<int> product_id_list)
        {
            product_id_list = product_id_list.Distinct().ToList();

            List<Product> product = dbContext.Products
                            .Where(p => product_id_list.Contains(p.ProductId)).ToList();

            if (product == null)
            {
                return NotFound();
            }
            return Ok(product);
        }

        [HttpDelete]
        [Route("{product_id}")]
        [Authorize(Roles = "Администратор магазина")]
        public async Task<ActionResult<List<Product>>> DeleteProduct(int product_id)
        {
            Product product = dbContext.Products.Find(product_id);
            if (product == null)
            {
                return BadRequest();
            }
            dbContext.Products.Remove(product);
            dbContext.SaveChanges();
            return Ok();
        }
        [HttpPost]
        [Authorize(Roles = "Администратор магазина")]
        public async Task<ActionResult<List<Product>>> AddProduct(ProductAdd product)
        {

            Product new_product = new Product()
            {
                ProductName = product.ProductName,
                ProductDescription = product.ProductDescription,
                ProductPrice = product.ProductPrice,
            };
            dbContext.Products.Add(new_product);
            dbContext.SaveChanges();
            return Ok(new_product);
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
