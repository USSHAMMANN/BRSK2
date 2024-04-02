using api_market.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace api_market.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ImagesController : ControllerBase
    {
        db_marketContext dbContext = new db_marketContext();

        [HttpGet]
        [Route("{product_id}")]
        public async Task<ActionResult> GetProductImages(int product_id)
        {
            var product = await dbContext.Products
                            .Include(p => p.ProductImages)
                            .FirstOrDefaultAsync(p => p.ProductId == product_id);
            if (product == null)
            {
                return NotFound();
            }
            return Ok(product.Images);
        }

        [HttpPost]
        [Authorize(Roles = "Администратор магазина")]
        [Route("{product_id}")]
        public async Task<ActionResult> AddProductImage(int product_id, [FromBody] string base64Image)
        {

            
            var product = await dbContext.Products.FindAsync(product_id);
            if (product == null)
            {
                return NotFound();
            }
            Console.WriteLine("Отправка изображения для товара: " + product_id);

            byte[] imageBytes = Convert.FromBase64String(base64Image);
            string uniqueFileName = $"{Guid.NewGuid()}.png";
            Console.WriteLine("Генерация названия изображения: " + uniqueFileName);

            string imagesDirectory = Path.Combine(Directory.GetCurrentDirectory(), "products", "images", product_id.ToString());

            Directory.CreateDirectory(imagesDirectory);
            Console.WriteLine("Создение директории: " + imagesDirectory);

            string imagePath = Path.Combine(imagesDirectory, uniqueFileName);
            Console.WriteLine("Создение пути изображения: " + imagePath);

            System.IO.File.WriteAllBytes(imagePath, imageBytes);
            Console.WriteLine("Запись изображения по пути: " + imagePath);

            dbContext.Add(new ProductImage
            {
                ProductId = product_id,
                ImageName = uniqueFileName,
            });
            dbContext.SaveChanges();
            Console.WriteLine("Сохранение информации в БД");
            return Ok();
        }
        [HttpGet]
        public async Task<ActionResult<List<ProductImage>>> GetImages()
        {
            List<ProductImage> productImages = dbContext.ProductImages.ToList();
            if (productImages == null)
            {
                return NotFound("Не найдено");
            }

            return Ok(productImages);

        }
        [HttpDelete]
        [Route("DeleteImage")]
        [Authorize(Roles = "Администратор магазина")]
        public async Task<ActionResult<List<ProductImage>>> DeleteImage(int product_image_id)
        {
            ProductImage productImage = dbContext.ProductImages.Find(product_image_id);
            if (productImage == null)
            {
                return BadRequest("Не найдено");
            }
            dbContext.ProductImages.Remove(productImage);
            dbContext.SaveChanges();

            return Ok("Изображение удалено");
        }
    }
}
