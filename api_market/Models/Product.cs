using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace api_market.Models
{
    public partial class Product
    {
        public Product()
        {
            OrderLists = new HashSet<OrderList>();
            ProductGenres = new HashSet<ProductGenre>();
            ProductImages = new HashSet<ProductImage>();
        }

        public int ProductId { get; set; }
        public string ProductName { get; set; } = null!;
        public string? ProductDescription { get; set; }
        public decimal ProductPrice { get; set; }
        [JsonIgnore]

        public virtual ICollection<OrderList> OrderLists { get; set; }
        public virtual ICollection<ProductGenre> ProductGenres { get; set; }
        public virtual ICollection<ProductImage> ProductImages { get; set; }
    }
}
