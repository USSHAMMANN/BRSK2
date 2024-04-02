namespace api_market.Models
{
    public class ProductAdd
    {
        public string ProductName { get; set; } = null!;
        public string? ProductDescription { get; set; }
        public decimal ProductPrice { get; set; }
    }
}
