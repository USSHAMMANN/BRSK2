using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using mvc_app.Api;
using mvc_app.Models;

namespace mvc_app.Controllers
{
    [Authorize]
    public class CartController : Controller
    {
        Cart cart;
        ApiOrder apiOrder;
        ApiProduct apiProduct;
        public CartController(IHttpContextAccessor httpContextAccessor)
        {
            cart = new Cart(httpContextAccessor);
            apiOrder = new ApiOrder(httpContextAccessor);
            apiProduct = new ApiProduct(httpContextAccessor);
        }
        public async Task<ActionResult> Index()
        {
            List<Product> products = await apiProduct.GetProductsRange(cart.GetCartList());
            ViewBag.CartCost = products.Select(x => x.ProductPrice).Sum();
            return View(products);
        }
        [HttpPost]
        [Authorize]
        public async Task<ActionResult> Ordering()
        {
            await apiOrder.Purchase(cart.GetCartList());
            cart.ClearCart();
            return RedirectToAction("Index");
        }
        [Authorize]
        public async Task<ActionResult> Delete(int product_id)
        {
            cart.RemoveFromCart(product_id);
            return RedirectToAction("Index");
        }
    }
}
