using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using mvc_app.Api;
using mvc_app.Models;

namespace mvc_app.Controllers
{
    public class ProductsController : Controller
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        ApiProduct apiProduct;
        ApiGenre apiGenre;
        ApiImages apiImages;
        Cart cart;

        public ProductsController(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
            apiProduct = new ApiProduct(httpContextAccessor);
            cart = new Cart(httpContextAccessor);
            apiImages = new ApiImages(httpContextAccessor);
        }

        public async Task<ActionResult> Index()
        {
            List<Product> products = await apiProduct.GetProducts();
            return View(products);
        }
        [HttpGet]
        public async Task<ActionResult> GetProductsByName(string product_name)
        {
            List<Product> products = new List<Product>(0);
            if (product_name == "" || product_name == null)
            {
                products = await apiProduct.GetProducts();
            }
            else
            {
                products = await apiProduct.GetProductByName(product_name);
            }

            return PartialView("_Products", products);
        }
        [Authorize]
        public async Task<ActionResult> Edit(int product_id)
        {
            Product product = await apiProduct.GetProduct(product_id);
            return View(product);
        }
        [HttpPost]
        [Authorize]
        public async Task<ActionResult> Edit(Product product)
        {
            apiProduct.EditProduct(product);
            return View();
        }
        [Authorize]
        public async Task<ActionResult> Detail(int product_id)
        {
            Product product = await apiProduct.GetProduct(product_id);
            return View(product);
        }

        [Authorize]
        public async Task<ActionResult> Create()
        {
            return View();
        }
        [HttpPost]
        [Authorize]
        public async Task<ActionResult> Create(ProductAdd product, IFormFile ProductImage)
        {

            Product currentProduct = await apiProduct.AddProduct(product);
            if (ProductImage != null)
            {
                using (var ms = new MemoryStream())
                {
                    ProductImage.CopyTo(ms);
                    var fileBytes = ms.ToArray();
                    string base64Image = Convert.ToBase64String(fileBytes);
                    await apiImages.AddImageToProduct(currentProduct.ProductId, base64Image);

                }
            }
            else
            {
                Console.WriteLine("Ошибка чтения изображения");
            }
            return RedirectToAction("Index");
        }
        [HttpPost]
        [Authorize]
        public async Task<ActionResult> AddToCart(int product_id)
        {
            cart.AddToCart(product_id);
            return RedirectToAction("Index");
        }
        public async Task<ActionResult> Delete(int product_id)
        {
            Product product = await apiProduct.GetProduct(product_id);
            return View(product);
        }
        public async Task<ActionResult> DeleteProduct(int ProductId) 
        {
            await apiProduct.DeleteProduct(ProductId);
            return RedirectToAction("Index");
        }
    }
}
