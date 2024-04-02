using mvc_app.Models;
using Newtonsoft.Json;
using System.Net;
using System.Text;

namespace mvc_app.Api
{
    public class ApiProduct: Api
    {
        public ApiProduct(IHttpContextAccessor httpContextAccessor) : base(httpContextAccessor)
        {
        }
        public async Task<List<Product>> GetProducts()
        {
            List<Product> products = new List<Product>();
            var response = await client.GetAsync($"Products");
            current_status = response.StatusCode;
            if (response.StatusCode == HttpStatusCode.OK)
            {
                products = JsonConvert.DeserializeObject<List<Product>>(response.Content.ReadAsStringAsync().Result);
            }

            return products;
        }
        public async Task<Product> GetProduct(int product_id)
        {
            Product product = new Product();
            var response = await client.GetAsync($"Products/{product_id}");
            current_status = response.StatusCode;
            if (response.StatusCode == HttpStatusCode.OK)
            {
                product = JsonConvert.DeserializeObject<Product>(response.Content.ReadAsStringAsync().Result);
            }

            return product;
        }

        public async Task<List<Product>> GetProductByName(string product_name)
        {
            List<Product> products = new List<Product>(0);
            var response = await client.GetAsync($"Products/ProductsByName/{product_name}");
            current_status = response.StatusCode;
            if (response.StatusCode == HttpStatusCode.OK)
            {
                products = JsonConvert.DeserializeObject<List<Product>>(response.Content.ReadAsStringAsync().Result);
            }

            return products;
        }

        public async Task<Product> AddProduct(ProductAdd product)
        {
            var json = JsonConvert.SerializeObject(product);
            var data = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await client.PostAsync($"Products", data);
            current_status = response.StatusCode;


            Product current_product = new Product();

            if (response.StatusCode == HttpStatusCode.OK)
            {
                current_product = JsonConvert.DeserializeObject<Product>(response.Content.ReadAsStringAsync().Result);
            }
            return current_product;
        }
        public async Task DeleteProduct(int product_id)
        {
            var response = await client.DeleteAsync($"Products/{product_id}");
            current_status = response.StatusCode;
            return;
        }
        public async Task EditProduct(Product product)
        {
            var json = JsonConvert.SerializeObject(product);
            var data = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await client.PutAsync($"Products", data);
            current_status = response.StatusCode;
            return;
        }
        public async Task<List<Product>> GetProductsRange(List<int> products_id)
        {
            List<Product> products = new List<Product>();

            var json = JsonConvert.SerializeObject(products_id);
            var data = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await client.PostAsync($"Products/ProductRangeList", data);
            current_status = response.StatusCode;
            if (response.StatusCode == HttpStatusCode.OK)
            {
                products = JsonConvert.DeserializeObject<List<Product>>(response.Content.ReadAsStringAsync().Result);
            }

            return products;
        }
    }
}
