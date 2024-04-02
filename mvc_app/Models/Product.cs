using System;
using System.Collections.Generic;

namespace mvc_app.Models
{
    public partial class Product
    {
        public int ProductId { get; set; }
        public string ProductName { get; set; } = null!;
        public string? ProductDescription { get; set; }
        public decimal? ProductPrice { get; set; }
    }
}
