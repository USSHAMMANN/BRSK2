using System;
using System.Collections.Generic;

namespace api_market.Models
{
    public partial class ProductImage
    {
        public int ImageId { get; set; }
        public int ProductId { get; set; }
        public string ImageName { get; set; } = null!;

        public virtual Product Product { get; set; } = null!;
    }
}
