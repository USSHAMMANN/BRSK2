using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace api_market.Models
{
    public partial class OrderList
    {
        public int OrderListId { get; set; }
        public int OrderId { get; set; }
        public int ProductId { get; set; }

        [JsonIgnore]
        public virtual Order Order { get; set; } = null!;
        public virtual Product Product { get; set; } = null!;
    }
}
