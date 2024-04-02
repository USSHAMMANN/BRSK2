using Newtonsoft.Json;
using System.Text;

namespace mvc_app.Api
{
    public class ApiImages : Api
    {
        public ApiImages(IHttpContextAccessor httpContextAccessor) : base(httpContextAccessor)
        {
        }


        public async Task AddImageToProduct(int product_id, string base64string)
        {
            var data = new StringContent(JsonConvert.SerializeObject(base64string), Encoding.UTF8, "application/json");
            var response = await client.PostAsync($"Images/{product_id}", data);
            current_status = response.StatusCode;
            return;
        }
        public static async Task<List<string>> GetProductImages(int product_id)
        {
            List<string> imagesString = new List<string>(0);
            var response = await client.GetAsync($"Images/{product_id}");
            imagesString = JsonConvert.DeserializeObject<List<string>>(response.Content.ReadAsStringAsync().Result);
            return imagesString;
        }
    }
}
