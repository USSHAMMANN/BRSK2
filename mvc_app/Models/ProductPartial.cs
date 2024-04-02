using mvc_app.Api;
using Newtonsoft.Json;
using System.Net;

namespace mvc_app.Models
{
    public partial class Product
    {
        public List<string> Images
        {
            get
            {
                List<string> images = Task.Run(() => ApiImages.GetProductImages(ProductId)).Result;
                return images;
            }
        }

        public string MainImage
        {
            get
            {
                if (Images.Count == 0)
                {
                    return null;
                }
                else 
                {
                    return "data:image/png;base64," + Images[0];
                }
            }
        }
    }

}
