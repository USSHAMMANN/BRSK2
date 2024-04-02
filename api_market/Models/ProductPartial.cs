using System.Text.Json.Serialization;

namespace api_market.Models
{
    public partial class Product
    {
        [JsonIgnore]
        public List<string> Images
        {
            get
            {
                string projectDirectory = System.IO.Directory.GetCurrentDirectory();
                if (ProductImages.Count == 0)
                {
                    return null;
                }

                List<string> data = new List<string>();
                foreach (var image in ProductImages)
                {
                    try
                    {
                        byte[] imageBytes = File.ReadAllBytes($"{projectDirectory}/products/images/{ProductId}/{image.ImageName}");


                        using (MemoryStream stream = new MemoryStream(imageBytes))
                        {
                            string base64String = Convert.ToBase64String(imageBytes);
                            data.Add(base64String);
                        }
                    }
                    catch (Exception)
                    {

                    }

                }
                return data;
            }
        }
    }
}
